Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - What is the file about?**

The first line of the code itself gives a massive clue: `go/src/cmd/compile/internal/ssa/func.go`. This immediately tells us we're in the Go compiler, specifically within the SSA (Static Single Assignment) intermediate representation. The filename "func.go" strongly suggests this file defines the structure and operations related to representing a Go function in SSA form.

**2. High-Level Structure Scan - What are the major components?**

A quick skim reveals a primary struct: `Func`. This is likely the core data structure representing a function in SSA. It has numerous fields, suggesting a complex and multifaceted role. We also see several helper functions and methods associated with `Func`.

**3. Deep Dive into the `Func` struct - What data does it hold?**

Now, let's systematically go through the fields of the `Func` struct, inferring their purpose:

* **Compiler Configuration:** `Config`, `Cache`, `fe` (Frontend) -  These point to the compiler's overall configuration, a cache for optimization, and the interface to the front-end of the compiler (parsing, type checking, etc.).
* **Current Compilation State:** `pass` - This likely tracks the current optimization pass being applied.
* **Function Identity:** `Name`, `Type` - Basic information about the function itself.
* **SSA Representation:** `Blocks`, `Entry` - The core of SSA: basic blocks of code and the entry point.
* **ID Allocation:** `bid`, `vid` -  Mechanisms to assign unique IDs to blocks and values within the SSA.
* **Debugging and Profiling:** `HTMLWriter`, `PrintOrHtmlSSA`, `ruleMatches` - Tools for visualizing and analyzing the SSA.
* **ABI Information:** `ABI0`, `ABI1`, `ABISelf`, `ABIDefault` - Details about the function's calling convention.
* **Compilation Flags/Properties:** `scheduled`, `laidout`, `NoSplit`, `dumpFileSeq`, `IsPgoHot` - Flags indicating the current state of compilation or specific function properties.
* **Register Allocation:** `RegAlloc`, `tempRegs` - Data structures related to assigning registers to variables.
* **Local Variable Management:** `NamedValues`, `Names`, `CanonicalLocalSlots`, `CanonicalLocalSplits` - How the compiler tracks and manages local variables.
* **Uncommon Path Handling:** `RegArgs`, `OwnAux` - Data for handling less frequent execution paths.
* **Closure Handling:** `CloSlot` - Specific to functions that are closures.
* **Free Lists:** `freeValues`, `freeBlocks` - Optimization to reuse memory for `Value` and `Block` objects.
* **Cached Analysis Results:** `cachedPostorder`, `cachedIdom`, `cachedSdom`, `cachedLoopnest`, `cachedLineStarts` - Storing results of expensive analyses to avoid recalculation.
* **Optimization Data:** `auxmap`, `constants` -  Data structures for common subexpression elimination and constant folding.

**4. Analyze the Methods - What operations can be performed?**

Next, examine the methods associated with `Func`:

* **Creation:** `NewFunc` -  How to instantiate a `Func` object.
* **ID Access:** `NumBlocks`, `NumValues` - Get the number of blocks and values.
* **Naming:** `NameABI`, `FuncNameABI` - Format the function name with ABI information.
* **Memory Management:** `newSparseSet`, `retSparseSet`, `newSparseMap`, `retSparseMap`, `newSparseMapPos`, `retSparseMapPos`, `newPoset`, `retPoset` -  Methods for allocating and freeing data structures, likely optimized for the compiler's needs.
* **Local Variable Manipulation:** `localSlotAddr`, `SplitString`, `SplitInterface`, `SplitSlice`, `SplitComplex`, `SplitInt64`, `SplitStruct`, `SplitArray`, `SplitSlot` - Key functions for breaking down composite local variables into their parts.
* **Value and Block Creation:** `newValue`, `newValueNoBlock`, `NewBlock` -  How to create new SSA values and basic blocks.
* **Logging and Debugging:** `LogStat` - For recording statistics.
* **Cache Management:** `unCacheLine`, `unCache`, `freeValue` -  Managing the constant cache.
* **Block Manipulation:** `freeBlock` - Freeing basic blocks.
* **Value Creation Helpers:** `NewValue0`, `NewValue0I`, `NewValue0A`, `NewValue0IA`, `NewValue1`, `NewValue1I`, `NewValue1A`, `NewValue1IA`, `NewValue2`, `NewValue2A`, `NewValue2I`, `NewValue2IA`, `NewValue3`, `NewValue3I`, `NewValue3A`, `NewValue4`, `NewValue4I` - Convenient methods to create `Value` objects with different numbers of arguments and aux values.
* **Constant Creation:** `constVal`, `ConstBool`, `ConstInt8`, `ConstInt16`, `ConstInt32`, `ConstInt64`, `ConstFloat32`, `ConstFloat64`, `ConstSlice`, `ConstInterface`, `ConstNil`, `ConstEmptyString`, `ConstOffPtrSP` -  Creating constant values of various types.
* **Accessors:** `Frontend`, `Warnl`, `Logf`, `Log` -  Methods to interact with the frontend.
* **Error Handling:** `Fatalf` -  Report fatal errors during compilation.
* **Control Flow Graph Analysis:** `postorder`, `Postorder`, `Idom`, `Sdom`, `loopnest`, `invalidateCFG` - Methods to perform analysis on the function's control flow graph.
* **Debugging Tools:** `DebugHashMatch`, `spSb`, `useFMA` - Functions for targeted debugging.
* **Local Variable Creation:** `NewLocal` - Create a new local variable.
* **Optimization Hints:** `IsMergeCandidate` - Determine if a local variable is a candidate for stack slot merging.

**5. Inferring Functionality - What Go features are being implemented?**

By connecting the data structures and methods, we can infer the high-level functionality:

* **Function Representation:** The `Func` struct is the central representation of a Go function during the SSA compilation phase.
* **SSA Construction:** The `NewBlock` and `newValue` (and its variants) methods are fundamental for building the SSA representation.
* **Local Variable Management:** The `Split...` methods suggest the implementation is dealing with how local variables (especially composite types) are laid out in memory and accessed.
* **Constant Handling:** The `constVal` and `Const...` methods indicate that the compiler optimizes constant values.
* **Control Flow Analysis:** The `postorder`, `Idom`, and `Sdom` methods point to the implementation of standard compiler analyses.
* **Optimization:** The presence of caches, free lists, and methods like `IsMergeCandidate` highlight the focus on optimization.
* **Debugging and Diagnostics:** The logging and HTML writing capabilities are crucial for compiler development and debugging.

**6. Code Examples - Illustrating inferred functionality.**

Based on the inferred functionality, we can create illustrative Go code examples:

* **Local Variable Splitting:** Demonstrating how a struct or interface local variable might be split into its constituent parts in SSA.
* **Constant Creation:** Showing how constant values are created and used in SSA.

**7. Command-Line Arguments and Error Handling - Connecting to the broader context.**

Consider how command-line arguments might influence the behavior. The `PrintOrHtmlSSA` field and the mention of `GOSSAFUNC` suggest environment variables control SSA dumping. The `Fatalf` method indicates how the compiler handles errors.

**8. Common Mistakes - Identifying potential pitfalls for users (compiler developers).**

Think about the constraints and invariants within the code. The need to `reset cache` before creating a new `Func` and the warnings about freeing values and blocks with uses or arguments point to common mistakes compiler developers might make when working with this code.

**Self-Correction/Refinement:**

During the process, I might realize that some initial assumptions were slightly off. For example, I might initially think `RegArgs` is purely for register allocation but then realize it's specifically for spilling/unspilling in uncommon paths. This iterative refinement is a natural part of understanding complex code. Also, noticing the different ABI fields (`ABI0`, `ABI1`, `ABISelf`, `ABIDefault`) prompts a closer look into how calling conventions are handled.

By following these steps, we can systematically analyze the given Go code snippet, understand its purpose within the Go compiler, and generate relevant explanations, examples, and insights.
这段代码是Go编译器中用于表示和操作函数（`Func`）的SSA（Static Single Assignment）中间表示的核心结构体及其相关方法。它在编译的中间阶段，将Go源代码转换为一种更适合优化的形式。

以下是 `Func` 结构体及其相关方法的主要功能：

**`Func` 结构体的功能：**

* **表示 Go 函数:**  `Func` 结构体代表一个 Go 函数声明或函数字面量及其函数体。每个被编译的函数都会创建一个新的 `Func` 实例。
* **存储函数信息:**  它包含了函数的各种元数据，例如：
    * `Config`: 目标架构的信息。
    * `Cache`: 用于缓存编译过程中可重用对象的缓存。
    * `fe`: 前端状态，提供与编译器前端的回调。
    * `pass`: 当前正在执行的编译Pass的信息。
    * `Name`: 函数名。
    * `Type`: 函数的类型签名。
* **存储 SSA 表示:** 核心的 SSA 图结构：
    * `Blocks`: 函数中所有基本块的无序集合。
    * `Entry`: 函数的入口基本块。
    * `bid`, `vid`: 用于分配基本块和值的唯一ID的分配器。
* **调试和分析:**
    * `HTMLWriter`: 用于生成HTML格式的SSA图，便于调试。
    * `PrintOrHtmlSSA`: 标记是否需要打印或生成HTML SSA。
    * `ruleMatches`: 记录在编译过程中特定规则匹配的次数。
* **ABI (Application Binary Interface) 信息:**
    * `ABI0`, `ABI1`, `ABISelf`, `ABIDefault`: 存储不同的ABI配置，用于处理函数调用约定。
* **编译状态标记:**
    * `scheduled`: 标记基本块中的值是否已完成最终排序。
    * `laidout`: 标记基本块是否已完成排序。
    * `NoSplit`: 标记函数是否禁止栈分裂。
    * `dumpFileSeq`: 用于生成dump文件的序列号。
    * `IsPgoHot`: 标记函数是否被PGO（Profile-Guided Optimization）认为是热点。
* **寄存器分配:**
    * `RegAlloc`: 存储寄存器分配的结果，将值ID映射到其所在的位置（寄存器或栈）。
    * `tempRegs`: 存储分配给临时指令的寄存器。
* **命名值 (Named Values):**
    * `NamedValues`: 将 `LocalSlot`（局部变量槽）映射到存储在该槽中的 `Value` 列表。
    * `Names`: `NamedValues` 的键的副本，用于保证迭代顺序的确定性。
    * `CanonicalLocalSlots`, `CanonicalLocalSplits`: 用于规范化局部变量槽，确保等价的槽是相等的。
* **参数处理:**
    * `RegArgs`: 存储在非常规函数入口路径中需要保存和恢复的寄存器-内存对。
    * `OwnAux`: 描述函数的参数和返回值。
    * `CloSlot`: 存储闭包指针的编译器合成名称。
* **内存管理优化:**
    * `freeValues`, `freeBlocks`: 使用链表维护空闲的 `Value` 和 `Block` 对象，以减少内存分配和垃圾回收的开销。
* **缓存的分析结果:**
    * `cachedPostorder`: 缓存的后序遍历结果。
    * `cachedIdom`: 缓存的直接支配节点。
    * `cachedSdom`: 缓存的支配树。
    * `cachedLoopnest`: 缓存的循环嵌套信息。
    * `cachedLineStarts`: 缓存的行号到整数的映射。
* **优化数据结构:**
    * `auxmap`: 用于CSE（Common Subexpression Elimination）的辅助值到不透明ID的映射。
    * `constants`: 用于缓存常量值的映射，键是常量值。

**`Func` 结构体相关方法的功能：**

* **`NewFunc(fe Frontend, cache *Cache) *Func`:** 创建一个新的空的 `Func` 对象。
* **`NumBlocks() int` 和 `NumValues() int`:** 返回大于函数中任何基本块或值的ID的整数。
* **`NameABI() string` 和 `FuncNameABI(n string, a obj.ABI) string`:** 返回包含函数名和ABI信息的字符串，用于调试和GOSSAFUNC。
* **`newSparseSet(n int) *sparseSet` 等 `newSparseMap` 系列方法:** 从缓存中分配稀疏集合和映射。
* **`localSlotAddr(slot LocalSlot) *LocalSlot`:** 获取规范化的 `LocalSlot` 地址。
* **`SplitString(name *LocalSlot) (*LocalSlot, *LocalSlot)` 等 `Split...` 系列方法:**  将复合类型的局部变量（如字符串、接口、切片、复数、结构体、数组）拆分成其组成部分的 `LocalSlot`。这是实现 SSA 的关键，因为它需要处理复合类型的内存布局。
* **`newValue(op Op, t *types.Type, b *Block, pos src.XPos) *Value` 和 `newValueNoBlock(...)`:** 创建新的 `Value` 对象，表示 SSA 中的一个操作。
* **`NewBlock(kind BlockKind) *Block`:** 创建新的基本块。
* **`LogStat(key string, args ...interface{})`:** 记录统计信息。
* **`unCacheLine(v *Value, aux int64) bool` 和 `unCache(v *Value)`:** 从常量缓存中移除值。
* **`freeValue(v *Value)` 和 `freeBlock(b *Block)`:** 释放不再使用的 `Value` 和 `Block` 对象。
* **`NewValue0(...)` 到 `NewValue4I(...)`:**  一系列便捷方法，用于在基本块中创建具有不同数量参数和辅助信息的 `Value` 对象。
* **`constVal(op Op, t *types.Type, c int64, setAuxInt bool) *Value`:** 从缓存中获取或创建常量值。
* **`ConstBool(t *types.Type, c bool) *Value` 等 `Const...` 系列方法:**  创建特定类型的常量值。
* **`Frontend() Frontend`, `Warnl(...)`, `Logf(...)`, `Log() bool`, `Fatalf(...)`:**  提供访问前端接口、记录日志和报告错误的方法。
* **`postorder() []*Block` 和 `Postorder() []*Block`:** 执行并返回基本块的后序遍历结果。
* **`Idom() []*Block` 和 `Sdom() SparseTree`:** 计算并返回直接支配节点和支配树。
* **`loopnest() *loopnest`:** 计算并返回循环嵌套信息。
* **`invalidateCFG()`:**  标记控制流图已更改，使缓存的分析结果失效。
* **`DebugHashMatch() bool`:** 用于条件性地启用调试输出。
* **`spSb() (sp, sb *Value)`:** 获取栈指针 (SP) 和静态基址寄存器 (SB) 的 `Value`。
* **`useFMA(v *Value) bool`:**  用于控制是否使用 FMA (Fused Multiply-Add) 指令。
* **`NewLocal(pos src.XPos, typ *types.Type) *ir.Name`:** 创建一个新的匿名局部变量。
* **`IsMergeCandidate(n *ir.Name) bool`:**  判断局部变量是否可以参与栈槽合并优化。

**推断的 Go 语言功能实现：**

这段代码是 Go 编译器中将 Go 源代码转换为 SSA 中间表示的核心部分。SSA 是一种重要的中间表示，它具有以下特点，使其更易于进行各种编译器优化：

* **静态单赋值:** 每个变量只被赋值一次。
* **显式的控制流:**  通过基本块和控制流边来明确表示程序的控制流程。

根据代码内容，可以推断出它涉及以下 Go 语言功能的实现：

* **变量和内存管理:**  `Split...` 方法展示了如何将 Go 语言中的复合类型（如结构体、数组、切片、接口等）在 SSA 中分解为更小的部分，以便进行更细粒度的操作和优化。这与 Go 的内存布局和变量访问密切相关。
* **常量处理:** `Const...` 方法展示了编译器如何识别和表示常量，并在后续的优化阶段利用这些常量。
* **函数调用:**  `ABI` 相关的字段表明这段代码处理了函数调用约定，包括参数传递、返回值处理等。
* **控制流结构:** `Blocks` 和 `Entry` 以及相关的 `postorder`, `Idom`, `Sdom`, `loopnest` 方法表明这段代码负责构建和分析 Go 程序的控制流图，这对于理解程序的执行路径和进行循环优化至关重要。
* **闭包:** `CloSlot` 字段表明代码正在处理 Go 语言的闭包特性。

**Go 代码示例：**

假设我们有以下简单的 Go 函数：

```go
package main

func add(a int, b int) int {
	sum := a + b
	return sum
}
```

当这个函数被编译并转换成 SSA 形式时，`Func` 结构体将会存储这个函数的信息。例如，`Blocks` 可能会包含以下基本块：

* **入口块:**  接收参数 `a` 和 `b`。
* **计算块:**  执行加法操作 `a + b`，并将结果赋值给 `sum`。
* **返回块:**  返回 `sum` 的值。

`newValue` 方法会被用来创建表示加法操作的 `Value`，它可能会有两个参数，分别对应 `a` 和 `b`。

**涉及到代码推理的示例：**

**假设输入:**  一个包含结构体变量的 Go 函数：

```go
package main

type Point struct {
	X int
	Y int
}

func processPoint(p Point) int {
	return p.X + p.Y
}
```

**SSA 构建过程中的推理:**

在 `processPoint` 函数的 SSA 构建过程中，当遇到访问结构体字段 `p.X` 和 `p.Y` 时，`SplitStruct` 方法可能会被调用。

**假设：** `p` 对应的 `LocalSlot` 名称为 `p_slot`。

**`f.SplitStruct(p_slot, 0)`**  可能会返回一个新的 `LocalSlot`，假设名为 `p_slot.X`，它对应于 `Point` 结构体的第一个字段 `X`。
**`f.SplitStruct(p_slot, 1)`**  可能会返回一个新的 `LocalSlot`，假设名为 `p_slot.Y`，它对应于 `Point` 结构体的第二个字段 `Y`。

然后，SSA 的值可能会使用这些拆分后的 `LocalSlot` 来表示对 `p.X` 和 `p.Y` 的访问。例如，可能会创建一个 `OpLoad` 操作来加载 `p_slot.X` 和 `p_slot.Y` 的值。

**输出（部分 SSA 表示的抽象示例）：**

```
b1: // 入口块
    v1 = SP // 栈指针
    v2 = Param <Point> // 参数 p
    // ...

b2: // 计算块
    v3 = SplitStruct <int> v2, 0 // 获取 p.X
    v4 = SplitStruct <int> v2, 1 // 获取 p.Y
    v5 = Load <int> v3        // 加载 p.X 的值
    v6 = Load <int> v4        // 加载 p.Y 的值
    v7 = Add <int> v5, v6    // 计算 p.X + p.Y
    // ...

b3: // 返回块
    Return v7
```

**命令行参数的具体处理：**

代码中提到了 `PrintOrHtmlSSA` 字段，它与 `GOSSAFUNC` 环境变量相关。

* **`GOSSAFUNC` 环境变量:**  当设置了 `GOSSAFUNC` 环境变量时，编译器会针对匹配该环境变量的函数生成 SSA 的文本或 HTML 输出。
* **`PrintOrHtmlSSA` 的作用:**  如果当前编译的函数名匹配 `GOSSAFUNC` 的值，`PrintOrHtmlSSA` 将被设置为 `true`。即使 `fe.Log()` 返回 `false`（表示通常不输出详细日志），也会强制进行 SSA 输出。
* **`HTMLWriter`:**  如果 `PrintOrHtmlSSA` 为 `true`，并且配置了 HTML 输出，`HTMLWriter` 会被用来生成带有图形表示的 SSA。

**示例：**

假设要查看 `add` 函数的 SSA：

```bash
export GOSSAFUNC=main.add
go build main.go
```

编译器会检测到 `GOSSAFUNC` 环境变量，并且由于当前编译的函数 `add` 匹配 `main.add`，`PrintOrHtmlSSA` 会被设置为 `true`，从而触发 SSA 的输出。

**使用者易犯错的点：**

这段代码主要由 Go 编译器的开发者使用，普通 Go 开发者不会直接操作这些结构。对于编译器开发者来说，一些容易犯错的点包括：

* **不正确地管理 `Value` 和 `Block` 的生命周期:** 例如，在它们仍然被使用时就调用 `freeValue` 或 `freeBlock`，会导致程序崩溃。代码中的检查 (`v.Uses != 0` 和 `len(v.Args) != 0`) 就是为了防止这种情况。
* **忘记调用 `invalidateCFG()`:**  当修改了函数的控制流图（例如，添加或删除了基本块或边）后，必须调用 `invalidateCFG()` 来清除缓存的分析结果，否则后续的分析可能会使用过时的信息，导致错误。
* **不正确地使用 `LocalSlot`:**  `LocalSlot` 代表局部变量在内存中的位置，不正确地拆分或使用 `LocalSlot` 会导致内存访问错误或类型不匹配。
* **在 `newValue` 或 `NewValue...` 方法中传递错误的参数类型或数量:** 这会导致创建的 SSA 图不正确。
* **在多线程环境下不正确地访问或修改 `Func` 的状态:** 虽然这段代码本身可能不是并发安全的，但如果编译过程涉及到并发，就需要特别注意对 `Func` 结构体的访问和修改。

总而言之，这段代码是 Go 编译器中至关重要的一部分，它定义了函数在 SSA 中间表示的形式，并提供了创建、操作和分析这种表示的工具。理解这段代码有助于深入了解 Go 编译器的内部工作原理。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/func.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"cmd/compile/internal/abi"
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/src"
	"fmt"
	"math"
	"strings"
)

// A Func represents a Go func declaration (or function literal) and its body.
// This package compiles each Func independently.
// Funcs are single-use; a new Func must be created for every compiled function.
type Func struct {
	Config *Config     // architecture information
	Cache  *Cache      // re-usable cache
	fe     Frontend    // frontend state associated with this Func, callbacks into compiler frontend
	pass   *pass       // current pass information (name, options, etc.)
	Name   string      // e.g. NewFunc or (*Func).NumBlocks (no package prefix)
	Type   *types.Type // type signature of the function.
	Blocks []*Block    // unordered set of all basic blocks (note: not indexable by ID)
	Entry  *Block      // the entry basic block

	bid idAlloc // block ID allocator
	vid idAlloc // value ID allocator

	HTMLWriter     *HTMLWriter    // html writer, for debugging
	PrintOrHtmlSSA bool           // true if GOSSAFUNC matches, true even if fe.Log() (spew phase results to stdout) is false.  There's an odd dependence on this in debug.go for method logf.
	ruleMatches    map[string]int // number of times countRule was called during compilation for any given string
	ABI0           *abi.ABIConfig // A copy, for no-sync access
	ABI1           *abi.ABIConfig // A copy, for no-sync access
	ABISelf        *abi.ABIConfig // ABI for function being compiled
	ABIDefault     *abi.ABIConfig // ABI for rtcall and other no-parsed-signature/pragma functions.

	scheduled   bool  // Values in Blocks are in final order
	laidout     bool  // Blocks are ordered
	NoSplit     bool  // true if function is marked as nosplit.  Used by schedule check pass.
	dumpFileSeq uint8 // the sequence numbers of dump file. (%s_%02d__%s.dump", funcname, dumpFileSeq, phaseName)
	IsPgoHot    bool

	// when register allocation is done, maps value ids to locations
	RegAlloc []Location

	// temporary registers allocated to rare instructions
	tempRegs map[ID]*Register

	// map from LocalSlot to set of Values that we want to store in that slot.
	NamedValues map[LocalSlot][]*Value
	// Names is a copy of NamedValues.Keys. We keep a separate list
	// of keys to make iteration order deterministic.
	Names []*LocalSlot
	// Canonicalize root/top-level local slots, and canonicalize their pieces.
	// Because LocalSlot pieces refer to their parents with a pointer, this ensures that equivalent slots really are equal.
	CanonicalLocalSlots  map[LocalSlot]*LocalSlot
	CanonicalLocalSplits map[LocalSlotSplitKey]*LocalSlot

	// RegArgs is a slice of register-memory pairs that must be spilled and unspilled in the uncommon path of function entry.
	RegArgs []Spill
	// OwnAux describes parameters and results for this function.
	OwnAux *AuxCall
	// CloSlot holds the compiler-synthesized name (".closureptr")
	// where we spill the closure pointer for range func bodies.
	CloSlot *ir.Name

	freeValues *Value // free Values linked by argstorage[0].  All other fields except ID are 0/nil.
	freeBlocks *Block // free Blocks linked by succstorage[0].b.  All other fields except ID are 0/nil.

	cachedPostorder  []*Block   // cached postorder traversal
	cachedIdom       []*Block   // cached immediate dominators
	cachedSdom       SparseTree // cached dominator tree
	cachedLoopnest   *loopnest  // cached loop nest information
	cachedLineStarts *xposmap   // cached map/set of xpos to integers

	auxmap    auxmap             // map from aux values to opaque ids used by CSE
	constants map[int64][]*Value // constants cache, keyed by constant value; users must check value's Op and Type
}

type LocalSlotSplitKey struct {
	parent *LocalSlot
	Off    int64       // offset of slot in N
	Type   *types.Type // type of slot
}

// NewFunc returns a new, empty function object.
// Caller must reset cache before calling NewFunc.
func (c *Config) NewFunc(fe Frontend, cache *Cache) *Func {
	return &Func{
		fe:     fe,
		Config: c,
		Cache:  cache,

		NamedValues:          make(map[LocalSlot][]*Value),
		CanonicalLocalSlots:  make(map[LocalSlot]*LocalSlot),
		CanonicalLocalSplits: make(map[LocalSlotSplitKey]*LocalSlot),
	}
}

// NumBlocks returns an integer larger than the id of any Block in the Func.
func (f *Func) NumBlocks() int {
	return f.bid.num()
}

// NumValues returns an integer larger than the id of any Value in the Func.
func (f *Func) NumValues() int {
	return f.vid.num()
}

// NameABI returns the function name followed by comma and the ABI number.
// This is intended for use with GOSSAFUNC and HTML dumps, and differs from
// the linker's "<1>" convention because "<" and ">" require shell quoting
// and are not legal file names (for use with GOSSADIR) on Windows.
func (f *Func) NameABI() string {
	return FuncNameABI(f.Name, f.ABISelf.Which())
}

// FuncNameABI returns n followed by a comma and the value of a.
// This is a separate function to allow a single point encoding
// of the format, which is used in places where there's not a Func yet.
func FuncNameABI(n string, a obj.ABI) string {
	return fmt.Sprintf("%s,%d", n, a)
}

// newSparseSet returns a sparse set that can store at least up to n integers.
func (f *Func) newSparseSet(n int) *sparseSet {
	return f.Cache.allocSparseSet(n)
}

// retSparseSet returns a sparse set to the config's cache of sparse
// sets to be reused by f.newSparseSet.
func (f *Func) retSparseSet(ss *sparseSet) {
	f.Cache.freeSparseSet(ss)
}

// newSparseMap returns a sparse map that can store at least up to n integers.
func (f *Func) newSparseMap(n int) *sparseMap {
	return f.Cache.allocSparseMap(n)
}

// retSparseMap returns a sparse map to the config's cache of sparse
// sets to be reused by f.newSparseMap.
func (f *Func) retSparseMap(ss *sparseMap) {
	f.Cache.freeSparseMap(ss)
}

// newSparseMapPos returns a sparse map that can store at least up to n integers.
func (f *Func) newSparseMapPos(n int) *sparseMapPos {
	return f.Cache.allocSparseMapPos(n)
}

// retSparseMapPos returns a sparse map to the config's cache of sparse
// sets to be reused by f.newSparseMapPos.
func (f *Func) retSparseMapPos(ss *sparseMapPos) {
	f.Cache.freeSparseMapPos(ss)
}

// newPoset returns a new poset from the internal cache
func (f *Func) newPoset() *poset {
	if len(f.Cache.scrPoset) > 0 {
		po := f.Cache.scrPoset[len(f.Cache.scrPoset)-1]
		f.Cache.scrPoset = f.Cache.scrPoset[:len(f.Cache.scrPoset)-1]
		return po
	}
	return newPoset()
}

// retPoset returns a poset to the internal cache
func (f *Func) retPoset(po *poset) {
	f.Cache.scrPoset = append(f.Cache.scrPoset, po)
}

func (f *Func) localSlotAddr(slot LocalSlot) *LocalSlot {
	a, ok := f.CanonicalLocalSlots[slot]
	if !ok {
		a = new(LocalSlot)
		*a = slot // don't escape slot
		f.CanonicalLocalSlots[slot] = a
	}
	return a
}

func (f *Func) SplitString(name *LocalSlot) (*LocalSlot, *LocalSlot) {
	ptrType := types.NewPtr(types.Types[types.TUINT8])
	lenType := types.Types[types.TINT]
	// Split this string up into two separate variables.
	p := f.SplitSlot(name, ".ptr", 0, ptrType)
	l := f.SplitSlot(name, ".len", ptrType.Size(), lenType)
	return p, l
}

func (f *Func) SplitInterface(name *LocalSlot) (*LocalSlot, *LocalSlot) {
	n := name.N
	u := types.Types[types.TUINTPTR]
	t := types.NewPtr(types.Types[types.TUINT8])
	// Split this interface up into two separate variables.
	sfx := ".itab"
	if n.Type().IsEmptyInterface() {
		sfx = ".type"
	}
	c := f.SplitSlot(name, sfx, 0, u) // see comment in typebits.Set
	d := f.SplitSlot(name, ".data", u.Size(), t)
	return c, d
}

func (f *Func) SplitSlice(name *LocalSlot) (*LocalSlot, *LocalSlot, *LocalSlot) {
	ptrType := types.NewPtr(name.Type.Elem())
	lenType := types.Types[types.TINT]
	p := f.SplitSlot(name, ".ptr", 0, ptrType)
	l := f.SplitSlot(name, ".len", ptrType.Size(), lenType)
	c := f.SplitSlot(name, ".cap", ptrType.Size()+lenType.Size(), lenType)
	return p, l, c
}

func (f *Func) SplitComplex(name *LocalSlot) (*LocalSlot, *LocalSlot) {
	s := name.Type.Size() / 2
	var t *types.Type
	if s == 8 {
		t = types.Types[types.TFLOAT64]
	} else {
		t = types.Types[types.TFLOAT32]
	}
	r := f.SplitSlot(name, ".real", 0, t)
	i := f.SplitSlot(name, ".imag", t.Size(), t)
	return r, i
}

func (f *Func) SplitInt64(name *LocalSlot) (*LocalSlot, *LocalSlot) {
	var t *types.Type
	if name.Type.IsSigned() {
		t = types.Types[types.TINT32]
	} else {
		t = types.Types[types.TUINT32]
	}
	if f.Config.BigEndian {
		return f.SplitSlot(name, ".hi", 0, t), f.SplitSlot(name, ".lo", t.Size(), types.Types[types.TUINT32])
	}
	return f.SplitSlot(name, ".hi", t.Size(), t), f.SplitSlot(name, ".lo", 0, types.Types[types.TUINT32])
}

func (f *Func) SplitStruct(name *LocalSlot, i int) *LocalSlot {
	st := name.Type
	return f.SplitSlot(name, st.FieldName(i), st.FieldOff(i), st.FieldType(i))
}
func (f *Func) SplitArray(name *LocalSlot) *LocalSlot {
	n := name.N
	at := name.Type
	if at.NumElem() != 1 {
		base.FatalfAt(n.Pos(), "bad array size")
	}
	et := at.Elem()
	return f.SplitSlot(name, "[0]", 0, et)
}

func (f *Func) SplitSlot(name *LocalSlot, sfx string, offset int64, t *types.Type) *LocalSlot {
	lssk := LocalSlotSplitKey{name, offset, t}
	if als, ok := f.CanonicalLocalSplits[lssk]; ok {
		return als
	}
	// Note: the _ field may appear several times.  But
	// have no fear, identically-named but distinct Autos are
	// ok, albeit maybe confusing for a debugger.
	ls := f.fe.SplitSlot(name, sfx, offset, t)
	f.CanonicalLocalSplits[lssk] = &ls
	return &ls
}

// newValue allocates a new Value with the given fields and places it at the end of b.Values.
func (f *Func) newValue(op Op, t *types.Type, b *Block, pos src.XPos) *Value {
	var v *Value
	if f.freeValues != nil {
		v = f.freeValues
		f.freeValues = v.argstorage[0]
		v.argstorage[0] = nil
	} else {
		ID := f.vid.get()
		if int(ID) < len(f.Cache.values) {
			v = &f.Cache.values[ID]
			v.ID = ID
		} else {
			v = &Value{ID: ID}
		}
	}
	v.Op = op
	v.Type = t
	v.Block = b
	if notStmtBoundary(op) {
		pos = pos.WithNotStmt()
	}
	v.Pos = pos
	b.Values = append(b.Values, v)
	return v
}

// newValueNoBlock allocates a new Value with the given fields.
// The returned value is not placed in any block.  Once the caller
// decides on a block b, it must set b.Block and append
// the returned value to b.Values.
func (f *Func) newValueNoBlock(op Op, t *types.Type, pos src.XPos) *Value {
	var v *Value
	if f.freeValues != nil {
		v = f.freeValues
		f.freeValues = v.argstorage[0]
		v.argstorage[0] = nil
	} else {
		ID := f.vid.get()
		if int(ID) < len(f.Cache.values) {
			v = &f.Cache.values[ID]
			v.ID = ID
		} else {
			v = &Value{ID: ID}
		}
	}
	v.Op = op
	v.Type = t
	v.Block = nil // caller must fix this.
	if notStmtBoundary(op) {
		pos = pos.WithNotStmt()
	}
	v.Pos = pos
	return v
}

// LogStat writes a string key and int value as a warning in a
// tab-separated format easily handled by spreadsheets or awk.
// file names, lines, and function names are included to provide enough (?)
// context to allow item-by-item comparisons across runs.
// For example:
// awk 'BEGIN {FS="\t"} $3~/TIME/{sum+=$4} END{print "t(ns)=",sum}' t.log
func (f *Func) LogStat(key string, args ...interface{}) {
	value := ""
	for _, a := range args {
		value += fmt.Sprintf("\t%v", a)
	}
	n := "missing_pass"
	if f.pass != nil {
		n = strings.Replace(f.pass.name, " ", "_", -1)
	}
	f.Warnl(f.Entry.Pos, "\t%s\t%s%s\t%s", n, key, value, f.Name)
}

// unCacheLine removes v from f's constant cache "line" for aux,
// resets v.InCache when it is found (and removed),
// and returns whether v was found in that line.
func (f *Func) unCacheLine(v *Value, aux int64) bool {
	vv := f.constants[aux]
	for i, cv := range vv {
		if v == cv {
			vv[i] = vv[len(vv)-1]
			vv[len(vv)-1] = nil
			f.constants[aux] = vv[0 : len(vv)-1]
			v.InCache = false
			return true
		}
	}
	return false
}

// unCache removes v from f's constant cache.
func (f *Func) unCache(v *Value) {
	if v.InCache {
		aux := v.AuxInt
		if f.unCacheLine(v, aux) {
			return
		}
		if aux == 0 {
			switch v.Op {
			case OpConstNil:
				aux = constNilMagic
			case OpConstSlice:
				aux = constSliceMagic
			case OpConstString:
				aux = constEmptyStringMagic
			case OpConstInterface:
				aux = constInterfaceMagic
			}
			if aux != 0 && f.unCacheLine(v, aux) {
				return
			}
		}
		f.Fatalf("unCached value %s not found in cache, auxInt=0x%x, adjusted aux=0x%x", v.LongString(), v.AuxInt, aux)
	}
}

// freeValue frees a value. It must no longer be referenced or have any args.
func (f *Func) freeValue(v *Value) {
	if v.Block == nil {
		f.Fatalf("trying to free an already freed value")
	}
	if v.Uses != 0 {
		f.Fatalf("value %s still has %d uses", v, v.Uses)
	}
	if len(v.Args) != 0 {
		f.Fatalf("value %s still has %d args", v, len(v.Args))
	}
	// Clear everything but ID (which we reuse).
	id := v.ID
	if v.InCache {
		f.unCache(v)
	}
	*v = Value{}
	v.ID = id
	v.argstorage[0] = f.freeValues
	f.freeValues = v
}

// NewBlock allocates a new Block of the given kind and places it at the end of f.Blocks.
func (f *Func) NewBlock(kind BlockKind) *Block {
	var b *Block
	if f.freeBlocks != nil {
		b = f.freeBlocks
		f.freeBlocks = b.succstorage[0].b
		b.succstorage[0].b = nil
	} else {
		ID := f.bid.get()
		if int(ID) < len(f.Cache.blocks) {
			b = &f.Cache.blocks[ID]
			b.ID = ID
		} else {
			b = &Block{ID: ID}
		}
	}
	b.Kind = kind
	b.Func = f
	b.Preds = b.predstorage[:0]
	b.Succs = b.succstorage[:0]
	b.Values = b.valstorage[:0]
	f.Blocks = append(f.Blocks, b)
	f.invalidateCFG()
	return b
}

func (f *Func) freeBlock(b *Block) {
	if b.Func == nil {
		f.Fatalf("trying to free an already freed block")
	}
	// Clear everything but ID (which we reuse).
	id := b.ID
	*b = Block{}
	b.ID = id
	b.succstorage[0].b = f.freeBlocks
	f.freeBlocks = b
}

// NewValue0 returns a new value in the block with no arguments and zero aux values.
func (b *Block) NewValue0(pos src.XPos, op Op, t *types.Type) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = 0
	v.Args = v.argstorage[:0]
	return v
}

// NewValue0I returns a new value in the block with no arguments and an auxint value.
func (b *Block) NewValue0I(pos src.XPos, op Op, t *types.Type, auxint int64) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = auxint
	v.Args = v.argstorage[:0]
	return v
}

// NewValue0A returns a new value in the block with no arguments and an aux value.
func (b *Block) NewValue0A(pos src.XPos, op Op, t *types.Type, aux Aux) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = 0
	v.Aux = aux
	v.Args = v.argstorage[:0]
	return v
}

// NewValue0IA returns a new value in the block with no arguments and both an auxint and aux values.
func (b *Block) NewValue0IA(pos src.XPos, op Op, t *types.Type, auxint int64, aux Aux) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = auxint
	v.Aux = aux
	v.Args = v.argstorage[:0]
	return v
}

// NewValue1 returns a new value in the block with one argument and zero aux values.
func (b *Block) NewValue1(pos src.XPos, op Op, t *types.Type, arg *Value) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = 0
	v.Args = v.argstorage[:1]
	v.argstorage[0] = arg
	arg.Uses++
	return v
}

// NewValue1I returns a new value in the block with one argument and an auxint value.
func (b *Block) NewValue1I(pos src.XPos, op Op, t *types.Type, auxint int64, arg *Value) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = auxint
	v.Args = v.argstorage[:1]
	v.argstorage[0] = arg
	arg.Uses++
	return v
}

// NewValue1A returns a new value in the block with one argument and an aux value.
func (b *Block) NewValue1A(pos src.XPos, op Op, t *types.Type, aux Aux, arg *Value) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = 0
	v.Aux = aux
	v.Args = v.argstorage[:1]
	v.argstorage[0] = arg
	arg.Uses++
	return v
}

// NewValue1IA returns a new value in the block with one argument and both an auxint and aux values.
func (b *Block) NewValue1IA(pos src.XPos, op Op, t *types.Type, auxint int64, aux Aux, arg *Value) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = auxint
	v.Aux = aux
	v.Args = v.argstorage[:1]
	v.argstorage[0] = arg
	arg.Uses++
	return v
}

// NewValue2 returns a new value in the block with two arguments and zero aux values.
func (b *Block) NewValue2(pos src.XPos, op Op, t *types.Type, arg0, arg1 *Value) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = 0
	v.Args = v.argstorage[:2]
	v.argstorage[0] = arg0
	v.argstorage[1] = arg1
	arg0.Uses++
	arg1.Uses++
	return v
}

// NewValue2A returns a new value in the block with two arguments and one aux values.
func (b *Block) NewValue2A(pos src.XPos, op Op, t *types.Type, aux Aux, arg0, arg1 *Value) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = 0
	v.Aux = aux
	v.Args = v.argstorage[:2]
	v.argstorage[0] = arg0
	v.argstorage[1] = arg1
	arg0.Uses++
	arg1.Uses++
	return v
}

// NewValue2I returns a new value in the block with two arguments and an auxint value.
func (b *Block) NewValue2I(pos src.XPos, op Op, t *types.Type, auxint int64, arg0, arg1 *Value) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = auxint
	v.Args = v.argstorage[:2]
	v.argstorage[0] = arg0
	v.argstorage[1] = arg1
	arg0.Uses++
	arg1.Uses++
	return v
}

// NewValue2IA returns a new value in the block with two arguments and both an auxint and aux values.
func (b *Block) NewValue2IA(pos src.XPos, op Op, t *types.Type, auxint int64, aux Aux, arg0, arg1 *Value) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = auxint
	v.Aux = aux
	v.Args = v.argstorage[:2]
	v.argstorage[0] = arg0
	v.argstorage[1] = arg1
	arg0.Uses++
	arg1.Uses++
	return v
}

// NewValue3 returns a new value in the block with three arguments and zero aux values.
func (b *Block) NewValue3(pos src.XPos, op Op, t *types.Type, arg0, arg1, arg2 *Value) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = 0
	v.Args = v.argstorage[:3]
	v.argstorage[0] = arg0
	v.argstorage[1] = arg1
	v.argstorage[2] = arg2
	arg0.Uses++
	arg1.Uses++
	arg2.Uses++
	return v
}

// NewValue3I returns a new value in the block with three arguments and an auxint value.
func (b *Block) NewValue3I(pos src.XPos, op Op, t *types.Type, auxint int64, arg0, arg1, arg2 *Value) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = auxint
	v.Args = v.argstorage[:3]
	v.argstorage[0] = arg0
	v.argstorage[1] = arg1
	v.argstorage[2] = arg2
	arg0.Uses++
	arg1.Uses++
	arg2.Uses++
	return v
}

// NewValue3A returns a new value in the block with three argument and an aux value.
func (b *Block) NewValue3A(pos src.XPos, op Op, t *types.Type, aux Aux, arg0, arg1, arg2 *Value) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = 0
	v.Aux = aux
	v.Args = v.argstorage[:3]
	v.argstorage[0] = arg0
	v.argstorage[1] = arg1
	v.argstorage[2] = arg2
	arg0.Uses++
	arg1.Uses++
	arg2.Uses++
	return v
}

// NewValue4 returns a new value in the block with four arguments and zero aux values.
func (b *Block) NewValue4(pos src.XPos, op Op, t *types.Type, arg0, arg1, arg2, arg3 *Value) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = 0
	v.Args = []*Value{arg0, arg1, arg2, arg3}
	arg0.Uses++
	arg1.Uses++
	arg2.Uses++
	arg3.Uses++
	return v
}

// NewValue4I returns a new value in the block with four arguments and auxint value.
func (b *Block) NewValue4I(pos src.XPos, op Op, t *types.Type, auxint int64, arg0, arg1, arg2, arg3 *Value) *Value {
	v := b.Func.newValue(op, t, b, pos)
	v.AuxInt = auxint
	v.Args = []*Value{arg0, arg1, arg2, arg3}
	arg0.Uses++
	arg1.Uses++
	arg2.Uses++
	arg3.Uses++
	return v
}

// constVal returns a constant value for c.
func (f *Func) constVal(op Op, t *types.Type, c int64, setAuxInt bool) *Value {
	if f.constants == nil {
		f.constants = make(map[int64][]*Value)
	}
	vv := f.constants[c]
	for _, v := range vv {
		if v.Op == op && v.Type.Compare(t) == types.CMPeq {
			if setAuxInt && v.AuxInt != c {
				panic(fmt.Sprintf("cached const %s should have AuxInt of %d", v.LongString(), c))
			}
			return v
		}
	}
	var v *Value
	if setAuxInt {
		v = f.Entry.NewValue0I(src.NoXPos, op, t, c)
	} else {
		v = f.Entry.NewValue0(src.NoXPos, op, t)
	}
	f.constants[c] = append(vv, v)
	v.InCache = true
	return v
}

// These magic auxint values let us easily cache non-numeric constants
// using the same constants map while making collisions unlikely.
// These values are unlikely to occur in regular code and
// are easy to grep for in case of bugs.
const (
	constSliceMagic       = 1122334455
	constInterfaceMagic   = 2233445566
	constNilMagic         = 3344556677
	constEmptyStringMagic = 4455667788
)

// ConstBool returns an int constant representing its argument.
func (f *Func) ConstBool(t *types.Type, c bool) *Value {
	i := int64(0)
	if c {
		i = 1
	}
	return f.constVal(OpConstBool, t, i, true)
}
func (f *Func) ConstInt8(t *types.Type, c int8) *Value {
	return f.constVal(OpConst8, t, int64(c), true)
}
func (f *Func) ConstInt16(t *types.Type, c int16) *Value {
	return f.constVal(OpConst16, t, int64(c), true)
}
func (f *Func) ConstInt32(t *types.Type, c int32) *Value {
	return f.constVal(OpConst32, t, int64(c), true)
}
func (f *Func) ConstInt64(t *types.Type, c int64) *Value {
	return f.constVal(OpConst64, t, c, true)
}
func (f *Func) ConstFloat32(t *types.Type, c float64) *Value {
	return f.constVal(OpConst32F, t, int64(math.Float64bits(float64(float32(c)))), true)
}
func (f *Func) ConstFloat64(t *types.Type, c float64) *Value {
	return f.constVal(OpConst64F, t, int64(math.Float64bits(c)), true)
}

func (f *Func) ConstSlice(t *types.Type) *Value {
	return f.constVal(OpConstSlice, t, constSliceMagic, false)
}
func (f *Func) ConstInterface(t *types.Type) *Value {
	return f.constVal(OpConstInterface, t, constInterfaceMagic, false)
}
func (f *Func) ConstNil(t *types.Type) *Value {
	return f.constVal(OpConstNil, t, constNilMagic, false)
}
func (f *Func) ConstEmptyString(t *types.Type) *Value {
	v := f.constVal(OpConstString, t, constEmptyStringMagic, false)
	v.Aux = StringToAux("")
	return v
}
func (f *Func) ConstOffPtrSP(t *types.Type, c int64, sp *Value) *Value {
	v := f.constVal(OpOffPtr, t, c, true)
	if len(v.Args) == 0 {
		v.AddArg(sp)
	}
	return v
}

func (f *Func) Frontend() Frontend                                  { return f.fe }
func (f *Func) Warnl(pos src.XPos, msg string, args ...interface{}) { f.fe.Warnl(pos, msg, args...) }
func (f *Func) Logf(msg string, args ...interface{})                { f.fe.Logf(msg, args...) }
func (f *Func) Log() bool                                           { return f.fe.Log() }

func (f *Func) Fatalf(msg string, args ...interface{}) {
	stats := "crashed"
	if f.Log() {
		f.Logf("  pass %s end %s\n", f.pass.name, stats)
		printFunc(f)
	}
	if f.HTMLWriter != nil {
		f.HTMLWriter.WritePhase(f.pass.name, fmt.Sprintf("%s <span class=\"stats\">%s</span>", f.pass.name, stats))
		f.HTMLWriter.flushPhases()
	}
	f.fe.Fatalf(f.Entry.Pos, msg, args...)
}

// postorder returns the reachable blocks in f in a postorder traversal.
func (f *Func) postorder() []*Block {
	if f.cachedPostorder == nil {
		f.cachedPostorder = postorder(f)
	}
	return f.cachedPostorder
}

func (f *Func) Postorder() []*Block {
	return f.postorder()
}

// Idom returns a map from block ID to the immediate dominator of that block.
// f.Entry.ID maps to nil. Unreachable blocks map to nil as well.
func (f *Func) Idom() []*Block {
	if f.cachedIdom == nil {
		f.cachedIdom = dominators(f)
	}
	return f.cachedIdom
}

// Sdom returns a sparse tree representing the dominator relationships
// among the blocks of f.
func (f *Func) Sdom() SparseTree {
	if f.cachedSdom == nil {
		f.cachedSdom = newSparseTree(f, f.Idom())
	}
	return f.cachedSdom
}

// loopnest returns the loop nest information for f.
func (f *Func) loopnest() *loopnest {
	if f.cachedLoopnest == nil {
		f.cachedLoopnest = loopnestfor(f)
	}
	return f.cachedLoopnest
}

// invalidateCFG tells f that its CFG has changed.
func (f *Func) invalidateCFG() {
	f.cachedPostorder = nil
	f.cachedIdom = nil
	f.cachedSdom = nil
	f.cachedLoopnest = nil
}

// DebugHashMatch returns
//
//	base.DebugHashMatch(this function's package.name)
//
// for use in bug isolation.  The return value is true unless
// environment variable GOCOMPILEDEBUG=gossahash=X is set, in which case "it depends on X".
// See [base.DebugHashMatch] for more information.
func (f *Func) DebugHashMatch() bool {
	if !base.HasDebugHash() {
		return true
	}
	sym := f.fe.Func().Sym()
	return base.DebugHashMatchPkgFunc(sym.Pkg.Path, sym.Name)
}

func (f *Func) spSb() (sp, sb *Value) {
	initpos := src.NoXPos // These are originally created with no position in ssa.go; if they are optimized out then recreated, should be the same.
	for _, v := range f.Entry.Values {
		if v.Op == OpSB {
			sb = v
		}
		if v.Op == OpSP {
			sp = v
		}
		if sb != nil && sp != nil {
			return
		}
	}
	if sb == nil {
		sb = f.Entry.NewValue0(initpos.WithNotStmt(), OpSB, f.Config.Types.Uintptr)
	}
	if sp == nil {
		sp = f.Entry.NewValue0(initpos.WithNotStmt(), OpSP, f.Config.Types.Uintptr)
	}
	return
}

// useFMA allows targeted debugging w/ GOFMAHASH
// If you have an architecture-dependent FP glitch, this will help you find it.
func (f *Func) useFMA(v *Value) bool {
	if !f.Config.UseFMA {
		return false
	}
	if base.FmaHash == nil {
		return true
	}
	return base.FmaHash.MatchPos(v.Pos, nil)
}

// NewLocal returns a new anonymous local variable of the given type.
func (f *Func) NewLocal(pos src.XPos, typ *types.Type) *ir.Name {
	nn := typecheck.TempAt(pos, f.fe.Func(), typ) // Note: adds new auto to fn.Dcl list
	nn.SetNonMergeable(true)
	return nn
}

// IsMergeCandidate returns true if variable n could participate in
// stack slot merging. For now we're restricting the set to things to
// items larger than what CanSSA would allow (approximateky, we disallow things
// marked as open defer slots so as to avoid complicating liveness
// analysis.
func IsMergeCandidate(n *ir.Name) bool {
	if base.Debug.MergeLocals == 0 ||
		base.Flag.N != 0 ||
		n.Class != ir.PAUTO ||
		n.Type().Size() <= int64(3*types.PtrSize) ||
		n.Addrtaken() ||
		n.NonMergeable() ||
		n.OpenDeferSlot() {
		return false
	}
	return true
}
```