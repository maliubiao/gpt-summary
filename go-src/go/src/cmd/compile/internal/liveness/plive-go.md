Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Request:** The request asks for the functionality of the provided Go code (`plive.go`), potential use cases with examples, handling of command-line flags, and common mistakes.

2. **Initial Scan and Keywords:**  Quickly read through the code, looking for prominent keywords and comments. "Garbage collector liveness bitmap generation" in the initial comment is a huge clue. Keywords like `liveness`, `bitvec`, `ssa`, `stackMap`, `safe point`, `clobber`, `-live` stand out. These immediately suggest the code is related to memory management and optimization within the Go compiler.

3. **Deconstruct the File Structure:** Note the package `liveness` and the import paths. The imports reveal dependencies on compiler internals (`cmd/compile/internal/...`) and runtime-related packages (`cmd/internal/obj`, `internal/abi`). This reinforces the idea that this code is deeply embedded in the compilation process.

4. **Identify Core Data Structures:** Pay close attention to the struct definitions.
    * `liveness`: This appears to be the central state container for the liveness analysis. Its fields (e.g., `fn`, `f`, `vars`, `idx`, `be`, `livevars`, `livenessMap`) hint at the different stages and data involved in the analysis.
    * `blockEffects`:  This likely holds information about how liveness changes within individual code blocks.
    * `Map`: This seems to map SSA values to stack map indices, which are crucial for the garbage collector.
    * `liveEffect`: This looks like a bitmask representing whether a variable is used or defined.

5. **Trace the Workflow (High-Level):** Look for functions that seem to orchestrate the analysis. `Compute` is a likely entry point due to its descriptive name and the fact it returns the `Map`. Within `Compute`, notice the call sequence: `getvariables`, `newliveness`, `prologue`, `solve`, `epilogue`, `emit`. This suggests a multi-stage process.

6. **Analyze Key Functionality:**  Examine the purpose of the core functions:
    * `getvariables`:  Identifies the variables to track for liveness. The `shouldTrack` function defines the criteria (on-stack, has pointers).
    * `newliveness`: Initializes the `liveness` struct, setting up the data structures needed for analysis.
    * `prologue`:  Performs an initial backward pass through blocks to determine which variables are used before being defined (`uevar`) and which are defined (`varkill`).
    * `solve`:  Implements the core dataflow analysis to determine `livein` and `liveout` for each block. This involves iteratively applying the liveness equations until convergence.
    * `epilogue`:  Performs a forward pass to identify safe points and construct the liveness bitmaps at those points. This is where the `livevars` are populated.
    * `compact`: Optimizes the liveness bitmaps by identifying and sharing identical bitmaps. This improves the efficiency of the generated metadata.
    * `emit`:  Generates the final output, the liveness bitmaps, as data structures that the garbage collector can use at runtime.
    * `markUnsafePoints`: Identifies points in the code where preemption (and thus garbage collection) is not allowed.
    * `clobber`:  Inserts instructions to overwrite dead variables with garbage data. This is an optimization for security and debugging.

7. **Identify Command-Line Flags:**  The comment at the beginning clearly mentions the `-live` flag and its levels. Note how the code uses `base.Flag.Live` to access this value.

8. **Infer Go Feature Implementation:** Based on the keywords and functionality, the most logical conclusion is that this code implements the **garbage collector's liveness analysis**. This analysis is critical for the garbage collector to know which memory locations contain live pointers at various points in the program's execution.

9. **Construct Go Code Example:**  Create a simple Go function that demonstrates a scenario where liveness analysis is important. Focus on how variable usage and definition affect what the garbage collector needs to track. A function with a local pointer variable being assigned and then used in a function call is a good starting point. Explain *why* the liveness analysis is needed in this scenario.

10. **Reason about Inputs and Outputs:** Consider the inputs to the `Compute` function (`ir.Func`, `ssa.Func`, `stkptrsize`) and its outputs (`Map`, `map[*ir.Name]bool`). Explain how the inputs represent the program's structure and the outputs provide the liveness information.

11. **Describe Command-Line Flag Handling:** Detail how the `-live` flag controls the level of debug output. Explain the meaning of each level (printing liveness lists, assembly listing with annotations).

12. **Identify Potential Mistakes:** Think about common errors developers might make that could be caught or influenced by liveness analysis. Examples include:
    * **Incorrect `OpVarDef` placement:** The comments in the code itself highlight this as a crucial aspect.
    * **Unintended variable liveness:**  If a variable is kept alive longer than necessary, it could lead to increased memory usage. While the developer might not directly *cause* this mistake, understanding liveness helps in optimizing code.

13. **Review and Refine:**  Read through the generated explanation, ensuring clarity, accuracy, and completeness. Organize the information logically. Make sure the Go code example is correct and illustrative. Double-check the description of the command-line flags and potential mistakes. For example, initially, I might have overlooked the details about `OpVarDef` and the importance of its placement, but the comments in the code highlighted this, prompting me to include it as a common mistake. Similarly, focusing on developer errors directly controlled by them is more helpful than abstractly saying "inefficient memory usage."

This step-by-step process, starting with a broad understanding and gradually diving into details, helps in effectively analyzing complex code like this. The keywords and comments are your best friends in quickly grasping the core purpose.
这段代码是 Go 编译器中 **垃圾回收器 (Garbage Collector, GC)** 的一部分，具体来说，它实现了 **活跃性分析 (Liveness Analysis)**，用于确定在程序的特定点上哪些变量包含指向堆内存的有效指针。这些信息对于垃圾回收器安全地回收不再使用的内存至关重要。

以下是 `plive.go` 的主要功能：

1. **定义 `OpVarDef` 注解:** 引入 `OpVarDef` 作为指令流中的一个标记，用于指示一个多字变量的完整初始化开始。这解决了指令流处理单字值而活跃性分析处理可能包含多个字的变量的问题。

2. **表示块效果 (`blockEffects`):** 定义了 `blockEffects` 结构体，用于总结 SSA (Static Single Assignment) 块的活跃性影响，包括：
   - `uevar` (upward exposed variables): 在块中被使用但在被赋值之前就存在的变量。
   - `varkill`: 在块中被赋值的变量。
   - `livein`: 在块入口处活跃的变量。
   - `liveout`: 在块出口处活跃的变量。

3. **维护全局活跃性状态 (`liveness`):** 定义了 `liveness` 结构体，用于存储进行活跃性分析所需的全局状态，例如：
   - 当前分析的函数 (`fn`, `f`).
   - 需要追踪的变量列表 (`vars`) 及其索引 (`idx`).
   - 栈指针大小 (`stkptrsize`).
   - 每个块的活跃性效果 (`be`).
   - 不安全点的信息 (`allUnsafe`, `unsafePoints`, `unsafeBlocks`).
   - 安全点处的活跃变量信息 (`livevars`).
   - 活跃性映射 (`livenessMap`) 和栈映射 (`stackMaps`).
   - 其他辅助信息，如部分活跃参数 (`partLiveArgs`) 和是否进行死变量覆写 (`doClobber`).

4. **识别需要追踪的变量 (`shouldTrack`):**  确定哪些栈上变量需要进行活跃性分析，通常是那些包含指针的局部变量和参数。

5. **计算变量的活跃性影响 (`valueEffects`):** 分析 SSA 值（指令）对变量的活跃性影响，判断变量是被使用 (`uevar`) 还是被赋值 (`varkill`)。

6. **执行活跃性分析的主流程 (`Compute`):**
   - 初始化活跃性分析状态 (`newliveness`).
   - 执行前向和后向的分析 (`prologue`, `solve`, `epilogue`)，使用数据流分析算法来计算每个程序点的活跃变量。
     - `prologue`: 初始化块效果，通过反向遍历块中的指令来计算 `uevar` 和 `varkill`。
     - `solve`:  通过迭代的方式解决活跃性数据流方程，计算每个块的 `livein` 和 `liveout`。
     - `epilogue`:  通过正向遍历块中的指令，在每个安全点记录活跃变量，并进行一些优化，如死变量覆写 (`clobber`) 和合并相同的活跃性位图 (`compact`).
   - 生成并输出活跃指针的位图 (`emit`)，这些位图会被垃圾回收器使用。

7. **处理不安全点 (`markUnsafePoints`):** 识别代码中不允许发生抢占 (preemption) 的点，这些点通常与某些原子操作或运行时内部机制相关。

8. **优化栈映射 (`compact`):**  通过合并相同的活跃性位图来减少元数据的大小。

9. **实现死变量覆写 (`clobber`):**  在安全点插入代码，用垃圾数据覆盖不再使用的栈变量，这有助于发现潜在的 use-after-free 错误，并可能提高安全性。

10. **输出调试信息 (`printDebug`):**  在 `-live` 标志开启时，打印详细的活跃性分析信息，用于调试和理解分析过程。

11. **生成 GC 元数据 (`emit`):**  将计算出的活跃性信息编码成运行时垃圾回收器可以理解的数据结构。

**推断的 Go 语言功能实现：垃圾回收 (Garbage Collection)**

这段代码是 Go 语言垃圾回收机制中不可或缺的一部分。活跃性分析是精确垃圾回收的关键，它使得垃圾回收器能够准确地识别哪些内存是正在使用的，哪些可以安全回收，避免悬挂指针和内存泄漏。

**Go 代码示例：**

```go
package main

import "fmt"

func foo() {
	var x *int
	a := 10
	x = &a // x 指向栈上的 a
	fmt.Println(*x)

	// 在这里，如果发生 GC，需要知道 x 是活跃的，因为它指向一个有效的内存地址。

	y := new(int) // y 指向堆上的内存
	*y = 20
	fmt.Println(*y)

	// 在这里，如果发生 GC，需要知道 y 是活跃的，因为它指向堆上的有效内存。

	z := make([]int, 5) // z 的底层数组在堆上
	z[0] = 30
	fmt.Println(z[0])

	// 在这里，如果发生 GC，需要知道 z 是活跃的，因为它包含指向堆的指针。

	x = nil // x 不再指向有效的内存地址

	// 在这里，如果发生 GC，可以安全回收之前 x 指向的栈内存 (如果 a 也变得不活跃)。
}

func main() {
	foo()
}
```

**假设的输入与输出（对于 `Compute` 函数）：**

**假设输入：**

- `curfn`:  表示 `foo` 函数的 `*ir.Func` 对象，包含了 `foo` 函数的抽象语法树信息。
- `f`: 表示 `foo` 函数的 `*ssa.Func` 对象，包含了 `foo` 函数的 SSA 中间表示。
- `stkptrsize`: 当前架构的栈指针大小，例如 8 (64 位架构) 或 4 (32 位架构)。
- `pp`: `*objw.Progs` 对象，用于生成目标代码。

**假设输出：**

- `Map`: 一个 `liveness.Map` 类型的映射，它将 `foo` 函数中可能发生 GC 的安全点（例如，函数调用、某些循环的入口等）映射到对应的栈映射索引。栈映射本身是一个位图，指示在该安全点上哪些变量包含指向堆的有效指针。例如，对于 `fmt.Println(*x)` 这一行，`Map` 可能会包含一个条目，指向一个栈映射，该栈映射指示变量 `x` 是活跃的。对于 `fmt.Println(*y)`，栈映射会指示 `y` 是活跃的。对于 `fmt.Println(z[0])`，栈映射会指示 `z` 是活跃的。
- `map[*ir.Name]bool`: 一个映射，指示 `foo` 函数的哪些输入参数可能部分活跃。例如，如果 `foo` 接受一个结构体参数，并且只使用了结构体的一部分字段，那么该参数会被标记为部分活跃。在这个简单的例子中，`foo` 没有参数，所以这个 map 可能是空的。

**命令行参数的具体处理：**

代码中提到了 `-live` 命令行标志，它控制着调试信息的输出级别：

- **`-live` 或 `-live=1`:**  在安全点以代码警告的形式打印活跃变量列表。当编译器遇到可能发生垃圾回收的点时，它会输出类似 `// live at call to fmt.Println: x` 的注释。
- **`-live=2`:** 除了 `-live=1` 的输出外，还会打印带有活跃性注释的汇编代码列表。这将生成更详细的输出，显示每条汇编指令执行前后哪些变量是活跃的。

这些标志通常通过 `go build` 或 `go run` 命令传递给编译器：

```bash
go build -gcflags=-live main.go  # 打印级别 1 的活跃性信息
go build -gcflags=-live=2 main.go # 打印级别 2 的活跃性信息
```

在 `plive.go` 中，这些标志的值是通过 `cmd/compile/internal/base` 包中的 `Flag` 变量来访问的，例如 `base.Flag.Live`。

**使用者易犯错的点：**

虽然开发者通常不会直接与 `plive.go` 中的代码交互，但理解其背后的概念可以帮助避免一些与内存管理相关的错误：

1. **误解 `OpVarDef` 的作用和放置：**  正如代码注释中强调的，`OpVarDef` 的位置至关重要。如果放置不当，可能会导致活跃性分析错误，从而影响垃圾回收的正确性。例如，在初始化多字变量之前放置 `OpVarDef` 是正确的，因为它告诉活跃性分析从该点开始跟踪变量的初始化过程。

   ```go
   // 正确的例子：
   // base, len, cap = pieces of x[1:]
   // OpVarDef x
   // x = {base, len, cap}

   // 错误的例子 1：
   // OpVarDef x
   // base, len, cap = pieces of x[1:]
   // x = {base, len, cap}

   // 错误的例子 2：
   // base, len, cap = pieces of x[1:]
   // x = {base, len, cap}
   // OpVarDef x
   ```

   在错误的例子中，活跃性分析可能会认为变量 `x` 的旧值或新值在某些时候是不需要的，从而导致错误的垃圾回收决策。

**总结：**

`plive.go` 是 Go 编译器中负责执行活跃性分析的关键部分。它通过数据流分析来确定程序执行过程中哪些变量包含有效的指针，并将这些信息提供给垃圾回收器，以实现安全和高效的内存管理。理解其功能有助于开发者更好地理解 Go 的内存管理机制。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/liveness/plive.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Garbage collector liveness bitmap generation.

// The command line flag -live causes this code to print debug information.
// The levels are:
//
//	-live (aka -live=1): print liveness lists as code warnings at safe points
//	-live=2: print an assembly listing with liveness annotations
//
// Each level includes the earlier output as well.

package liveness

import (
	"cmp"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	"cmd/compile/internal/abi"
	"cmd/compile/internal/base"
	"cmd/compile/internal/bitvec"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/objw"
	"cmd/compile/internal/reflectdata"
	"cmd/compile/internal/ssa"
	"cmd/compile/internal/typebits"
	"cmd/compile/internal/types"
	"cmd/internal/hash"
	"cmd/internal/obj"
	"cmd/internal/src"

	rtabi "internal/abi"
)

// OpVarDef is an annotation for the liveness analysis, marking a place
// where a complete initialization (definition) of a variable begins.
// Since the liveness analysis can see initialization of single-word
// variables quite easy, OpVarDef is only needed for multi-word
// variables satisfying isfat(n.Type). For simplicity though, buildssa
// emits OpVarDef regardless of variable width.
//
// An 'OpVarDef x' annotation in the instruction stream tells the liveness
// analysis to behave as though the variable x is being initialized at that
// point in the instruction stream. The OpVarDef must appear before the
// actual (multi-instruction) initialization, and it must also appear after
// any uses of the previous value, if any. For example, if compiling:
//
//	x = x[1:]
//
// it is important to generate code like:
//
//	base, len, cap = pieces of x[1:]
//	OpVarDef x
//	x = {base, len, cap}
//
// If instead the generated code looked like:
//
//	OpVarDef x
//	base, len, cap = pieces of x[1:]
//	x = {base, len, cap}
//
// then the liveness analysis would decide the previous value of x was
// unnecessary even though it is about to be used by the x[1:] computation.
// Similarly, if the generated code looked like:
//
//	base, len, cap = pieces of x[1:]
//	x = {base, len, cap}
//	OpVarDef x
//
// then the liveness analysis will not preserve the new value of x, because
// the OpVarDef appears to have "overwritten" it.
//
// OpVarDef is a bit of a kludge to work around the fact that the instruction
// stream is working on single-word values but the liveness analysis
// wants to work on individual variables, which might be multi-word
// aggregates. It might make sense at some point to look into letting
// the liveness analysis work on single-word values as well, although
// there are complications around interface values, slices, and strings,
// all of which cannot be treated as individual words.

// blockEffects summarizes the liveness effects on an SSA block.
type blockEffects struct {
	// Computed during Liveness.prologue using only the content of
	// individual blocks:
	//
	//	uevar: upward exposed variables (used before set in block)
	//	varkill: killed variables (set in block)
	uevar   bitvec.BitVec
	varkill bitvec.BitVec

	// Computed during Liveness.solve using control flow information:
	//
	//	livein: variables live at block entry
	//	liveout: variables live at block exit
	livein  bitvec.BitVec
	liveout bitvec.BitVec
}

// A collection of global state used by liveness analysis.
type liveness struct {
	fn         *ir.Func
	f          *ssa.Func
	vars       []*ir.Name
	idx        map[*ir.Name]int32
	stkptrsize int64

	be []blockEffects

	// allUnsafe indicates that all points in this function are
	// unsafe-points.
	allUnsafe bool
	// unsafePoints bit i is set if Value ID i is an unsafe-point
	// (preemption is not allowed). Only valid if !allUnsafe.
	unsafePoints bitvec.BitVec
	// unsafeBlocks bit i is set if Block ID i is an unsafe-point
	// (preemption is not allowed on any end-of-block
	// instructions). Only valid if !allUnsafe.
	unsafeBlocks bitvec.BitVec

	// An array with a bit vector for each safe point in the
	// current Block during liveness.epilogue. Indexed in Value
	// order for that block. Additionally, for the entry block
	// livevars[0] is the entry bitmap. liveness.compact moves
	// these to stackMaps.
	livevars []bitvec.BitVec

	// livenessMap maps from safe points (i.e., CALLs) to their
	// liveness map indexes.
	livenessMap Map
	stackMapSet bvecSet
	stackMaps   []bitvec.BitVec

	cache progeffectscache

	// partLiveArgs includes input arguments (PPARAM) that may
	// be partially live. That is, it is considered live because
	// a part of it is used, but we may not initialize all parts.
	partLiveArgs map[*ir.Name]bool

	doClobber     bool // Whether to clobber dead stack slots in this function.
	noClobberArgs bool // Do not clobber function arguments

	// treat "dead" writes as equivalent to reads during the analysis;
	// used only during liveness analysis for stack slot merging (doesn't
	// make sense for stackmap analysis).
	conservativeWrites bool
}

// Map maps from *ssa.Value to StackMapIndex.
// Also keeps track of unsafe ssa.Values and ssa.Blocks.
// (unsafe = can't be interrupted during GC.)
type Map struct {
	Vals         map[ssa.ID]objw.StackMapIndex
	UnsafeVals   map[ssa.ID]bool
	UnsafeBlocks map[ssa.ID]bool
	// The set of live, pointer-containing variables at the DeferReturn
	// call (only set when open-coded defers are used).
	DeferReturn objw.StackMapIndex
}

func (m *Map) reset() {
	if m.Vals == nil {
		m.Vals = make(map[ssa.ID]objw.StackMapIndex)
		m.UnsafeVals = make(map[ssa.ID]bool)
		m.UnsafeBlocks = make(map[ssa.ID]bool)
	} else {
		clear(m.Vals)
		clear(m.UnsafeVals)
		clear(m.UnsafeBlocks)
	}
	m.DeferReturn = objw.StackMapDontCare
}

func (m *Map) set(v *ssa.Value, i objw.StackMapIndex) {
	m.Vals[v.ID] = i
}
func (m *Map) setUnsafeVal(v *ssa.Value) {
	m.UnsafeVals[v.ID] = true
}
func (m *Map) setUnsafeBlock(b *ssa.Block) {
	m.UnsafeBlocks[b.ID] = true
}

func (m Map) Get(v *ssa.Value) objw.StackMapIndex {
	// If v isn't in the map, then it's a "don't care".
	if idx, ok := m.Vals[v.ID]; ok {
		return idx
	}
	return objw.StackMapDontCare
}
func (m Map) GetUnsafe(v *ssa.Value) bool {
	// default is safe
	return m.UnsafeVals[v.ID]
}
func (m Map) GetUnsafeBlock(b *ssa.Block) bool {
	// default is safe
	return m.UnsafeBlocks[b.ID]
}

type progeffectscache struct {
	retuevar    []int32
	tailuevar   []int32
	initialized bool
}

// shouldTrack reports whether the liveness analysis
// should track the variable n.
// We don't care about variables that have no pointers,
// nor do we care about non-local variables,
// nor do we care about empty structs (handled by the pointer check),
// nor do we care about the fake PAUTOHEAP variables.
func shouldTrack(n *ir.Name) bool {
	return (n.Class == ir.PAUTO && n.Esc() != ir.EscHeap || n.Class == ir.PPARAM || n.Class == ir.PPARAMOUT) && n.Type().HasPointers()
}

// getvariables returns the list of on-stack variables that we need to track
// and a map for looking up indices by *Node.
func getvariables(fn *ir.Func) ([]*ir.Name, map[*ir.Name]int32) {
	var vars []*ir.Name
	for _, n := range fn.Dcl {
		if shouldTrack(n) {
			vars = append(vars, n)
		}
	}
	idx := make(map[*ir.Name]int32, len(vars))
	for i, n := range vars {
		idx[n] = int32(i)
	}
	return vars, idx
}

func (lv *liveness) initcache() {
	if lv.cache.initialized {
		base.Fatalf("liveness cache initialized twice")
		return
	}
	lv.cache.initialized = true

	for i, node := range lv.vars {
		switch node.Class {
		case ir.PPARAM:
			// A return instruction with a p.to is a tail return, which brings
			// the stack pointer back up (if it ever went down) and then jumps
			// to a new function entirely. That form of instruction must read
			// all the parameters for correctness, and similarly it must not
			// read the out arguments - they won't be set until the new
			// function runs.
			lv.cache.tailuevar = append(lv.cache.tailuevar, int32(i))

		case ir.PPARAMOUT:
			// All results are live at every return point.
			// Note that this point is after escaping return values
			// are copied back to the stack using their PAUTOHEAP references.
			lv.cache.retuevar = append(lv.cache.retuevar, int32(i))
		}
	}
}

// A liveEffect is a set of flags that describe an instruction's
// liveness effects on a variable.
//
// The possible flags are:
//
//	uevar - used by the instruction
//	varkill - killed by the instruction (set)
//
// A kill happens after the use (for an instruction that updates a value, for example).
type liveEffect int

const (
	uevar liveEffect = 1 << iota
	varkill
)

// valueEffects returns the index of a variable in lv.vars and the
// liveness effects v has on that variable.
// If v does not affect any tracked variables, it returns -1, 0.
func (lv *liveness) valueEffects(v *ssa.Value) (int32, liveEffect) {
	n, e := affectedVar(v)
	if e == 0 || n == nil { // cheapest checks first
		return -1, 0
	}
	// AllocFrame has dropped unused variables from
	// lv.fn.Func.Dcl, but they might still be referenced by
	// OpVarFoo pseudo-ops. Ignore them to prevent "lost track of
	// variable" ICEs (issue 19632).
	switch v.Op {
	case ssa.OpVarDef, ssa.OpVarLive, ssa.OpKeepAlive:
		if !n.Used() {
			return -1, 0
		}
	}

	if n.Class == ir.PPARAM && !n.Addrtaken() && n.Type().Size() > int64(types.PtrSize) {
		// Only aggregate-typed arguments that are not address-taken can be
		// partially live.
		lv.partLiveArgs[n] = true
	}

	var effect liveEffect
	// Read is a read, obviously.
	//
	// Addr is a read also, as any subsequent holder of the pointer must be able
	// to see all the values (including initialization) written so far.
	// This also prevents a variable from "coming back from the dead" and presenting
	// stale pointers to the garbage collector. See issue 28445.
	if e&(ssa.SymRead|ssa.SymAddr) != 0 {
		effect |= uevar
	}
	if e&ssa.SymWrite != 0 {
		if !isfat(n.Type()) || v.Op == ssa.OpVarDef {
			effect |= varkill
		} else if lv.conservativeWrites {
			effect |= uevar
		}
	}

	if effect == 0 {
		return -1, 0
	}

	if pos, ok := lv.idx[n]; ok {
		return pos, effect
	}
	return -1, 0
}

// affectedVar returns the *ir.Name node affected by v.
func affectedVar(v *ssa.Value) (*ir.Name, ssa.SymEffect) {
	// Special cases.
	switch v.Op {
	case ssa.OpLoadReg:
		n, _ := ssa.AutoVar(v.Args[0])
		return n, ssa.SymRead
	case ssa.OpStoreReg:
		n, _ := ssa.AutoVar(v)
		return n, ssa.SymWrite

	case ssa.OpArgIntReg:
		// This forces the spill slot for the register to be live at function entry.
		// one of the following holds for a function F with pointer-valued register arg X:
		//  0. No GC (so an uninitialized spill slot is okay)
		//  1. GC at entry of F.  GC is precise, but the spills around morestack initialize X's spill slot
		//  2. Stack growth at entry of F.  Same as GC.
		//  3. GC occurs within F itself.  This has to be from preemption, and thus GC is conservative.
		//     a. X is in a register -- then X is seen, and the spill slot is also scanned conservatively.
		//     b. X is spilled -- the spill slot is initialized, and scanned conservatively
		//     c. X is not live -- the spill slot is scanned conservatively, and it may contain X from an earlier spill.
		//  4. GC within G, transitively called from F
		//    a. X is live at call site, therefore is spilled, to its spill slot (which is live because of subsequent LoadReg).
		//    b. X is not live at call site -- but neither is its spill slot.
		n, _ := ssa.AutoVar(v)
		return n, ssa.SymRead

	case ssa.OpVarLive:
		return v.Aux.(*ir.Name), ssa.SymRead
	case ssa.OpVarDef:
		return v.Aux.(*ir.Name), ssa.SymWrite
	case ssa.OpKeepAlive:
		n, _ := ssa.AutoVar(v.Args[0])
		return n, ssa.SymRead
	}

	e := v.Op.SymEffect()
	if e == 0 {
		return nil, 0
	}

	switch a := v.Aux.(type) {
	case nil, *obj.LSym:
		// ok, but no node
		return nil, e
	case *ir.Name:
		return a, e
	default:
		base.Fatalf("weird aux: %s", v.LongString())
		return nil, e
	}
}

type livenessFuncCache struct {
	be          []blockEffects
	livenessMap Map
}

// Constructs a new liveness structure used to hold the global state of the
// liveness computation. The cfg argument is a slice of *BasicBlocks and the
// vars argument is a slice of *Nodes.
func newliveness(fn *ir.Func, f *ssa.Func, vars []*ir.Name, idx map[*ir.Name]int32, stkptrsize int64) *liveness {
	lv := &liveness{
		fn:         fn,
		f:          f,
		vars:       vars,
		idx:        idx,
		stkptrsize: stkptrsize,
	}

	// Significant sources of allocation are kept in the ssa.Cache
	// and reused. Surprisingly, the bit vectors themselves aren't
	// a major source of allocation, but the liveness maps are.
	if lc, _ := f.Cache.Liveness.(*livenessFuncCache); lc == nil {
		// Prep the cache so liveness can fill it later.
		f.Cache.Liveness = new(livenessFuncCache)
	} else {
		if cap(lc.be) >= f.NumBlocks() {
			lv.be = lc.be[:f.NumBlocks()]
		}
		lv.livenessMap = Map{
			Vals:         lc.livenessMap.Vals,
			UnsafeVals:   lc.livenessMap.UnsafeVals,
			UnsafeBlocks: lc.livenessMap.UnsafeBlocks,
			DeferReturn:  objw.StackMapDontCare,
		}
		lc.livenessMap.Vals = nil
		lc.livenessMap.UnsafeVals = nil
		lc.livenessMap.UnsafeBlocks = nil
	}
	if lv.be == nil {
		lv.be = make([]blockEffects, f.NumBlocks())
	}

	nblocks := int32(len(f.Blocks))
	nvars := int32(len(vars))
	bulk := bitvec.NewBulk(nvars, nblocks*7, fn.Pos())
	for _, b := range f.Blocks {
		be := lv.blockEffects(b)

		be.uevar = bulk.Next()
		be.varkill = bulk.Next()
		be.livein = bulk.Next()
		be.liveout = bulk.Next()
	}
	lv.livenessMap.reset()

	lv.markUnsafePoints()

	lv.partLiveArgs = make(map[*ir.Name]bool)

	lv.enableClobber()

	return lv
}

func (lv *liveness) blockEffects(b *ssa.Block) *blockEffects {
	return &lv.be[b.ID]
}

// Generates live pointer value maps for arguments and local variables. The
// this argument and the in arguments are always assumed live. The vars
// argument is a slice of *Nodes.
func (lv *liveness) pointerMap(liveout bitvec.BitVec, vars []*ir.Name, args, locals bitvec.BitVec) {
	var slotsSeen map[int64]*ir.Name
	checkForDuplicateSlots := base.Debug.MergeLocals != 0
	if checkForDuplicateSlots {
		slotsSeen = make(map[int64]*ir.Name)
	}
	for i := int32(0); ; i++ {
		i = liveout.Next(i)
		if i < 0 {
			break
		}
		node := vars[i]
		switch node.Class {
		case ir.PPARAM, ir.PPARAMOUT:
			if !node.IsOutputParamInRegisters() {
				if node.FrameOffset() < 0 {
					lv.f.Fatalf("Node %v has frameoffset %d\n", node.Sym().Name, node.FrameOffset())
				}
				typebits.SetNoCheck(node.Type(), node.FrameOffset(), args)
				break
			}
			fallthrough // PPARAMOUT in registers acts memory-allocates like an AUTO
		case ir.PAUTO:
			if checkForDuplicateSlots {
				if prev, ok := slotsSeen[node.FrameOffset()]; ok {
					base.FatalfAt(node.Pos(), "two vars live at pointerMap generation: %q and %q", prev.Sym().Name, node.Sym().Name)
				}
				slotsSeen[node.FrameOffset()] = node
			}
			typebits.Set(node.Type(), node.FrameOffset()+lv.stkptrsize, locals)
		}
	}
}

// IsUnsafe indicates that all points in this function are
// unsafe-points.
func IsUnsafe(f *ssa.Func) bool {
	// The runtime assumes the only safe-points are function
	// prologues (because that's how it used to be). We could and
	// should improve that, but for now keep consider all points
	// in the runtime unsafe. obj will add prologues and their
	// safe-points.
	//
	// go:nosplit functions are similar. Since safe points used to
	// be coupled with stack checks, go:nosplit often actually
	// means "no safe points in this function".
	return base.Flag.CompilingRuntime || f.NoSplit
}

// markUnsafePoints finds unsafe points and computes lv.unsafePoints.
func (lv *liveness) markUnsafePoints() {
	if IsUnsafe(lv.f) {
		// No complex analysis necessary.
		lv.allUnsafe = true
		return
	}

	lv.unsafePoints = bitvec.New(int32(lv.f.NumValues()))
	lv.unsafeBlocks = bitvec.New(int32(lv.f.NumBlocks()))

	// Mark architecture-specific unsafe points.
	for _, b := range lv.f.Blocks {
		for _, v := range b.Values {
			if v.Op.UnsafePoint() {
				lv.unsafePoints.Set(int32(v.ID))
			}
		}
	}

	for _, b := range lv.f.Blocks {
		for _, v := range b.Values {
			if v.Op != ssa.OpWBend {
				continue
			}
			// WBend appears at the start of a block, like this:
			//    ...
			//    if wbEnabled: goto C else D
			// C:
			//    ... some write barrier enabled code ...
			//    goto B
			// D:
			//    ... some write barrier disabled code ...
			//    goto B
			// B:
			//    m1 = Phi mem_C mem_D
			//    m2 = store operation ... m1
			//    m3 = store operation ... m2
			//    m4 = WBend m3

			// Find first memory op in the block, which should be a Phi.
			m := v
			for {
				m = m.MemoryArg()
				if m.Block != b {
					lv.f.Fatalf("can't find Phi before write barrier end mark %v", v)
				}
				if m.Op == ssa.OpPhi {
					break
				}
			}
			// Find the two predecessor blocks (write barrier on and write barrier off)
			if len(m.Args) != 2 {
				lv.f.Fatalf("phi before write barrier end mark has %d args, want 2", len(m.Args))
			}
			c := b.Preds[0].Block()
			d := b.Preds[1].Block()

			// Find their common predecessor block (the one that branches based on wb on/off).
			// It might be a diamond pattern, or one of the blocks in the diamond pattern might
			// be missing.
			var decisionBlock *ssa.Block
			if len(c.Preds) == 1 && c.Preds[0].Block() == d {
				decisionBlock = d
			} else if len(d.Preds) == 1 && d.Preds[0].Block() == c {
				decisionBlock = c
			} else if len(c.Preds) == 1 && len(d.Preds) == 1 && c.Preds[0].Block() == d.Preds[0].Block() {
				decisionBlock = c.Preds[0].Block()
			} else {
				lv.f.Fatalf("can't find write barrier pattern %v", v)
			}
			if len(decisionBlock.Succs) != 2 {
				lv.f.Fatalf("common predecessor block the wrong type %s", decisionBlock.Kind)
			}

			// Flow backwards from the control value to find the
			// flag load. We don't know what lowered ops we're
			// looking for, but all current arches produce a
			// single op that does the memory load from the flag
			// address, so we look for that.
			var load *ssa.Value
			v := decisionBlock.Controls[0]
			for {
				if v.MemoryArg() != nil {
					// Single instruction to load (and maybe compare) the write barrier flag.
					if sym, ok := v.Aux.(*obj.LSym); ok && sym == ir.Syms.WriteBarrier {
						load = v
						break
					}
					// Some architectures have to materialize the address separate from
					// the load.
					if sym, ok := v.Args[0].Aux.(*obj.LSym); ok && sym == ir.Syms.WriteBarrier {
						load = v
						break
					}
					v.Fatalf("load of write barrier flag not from correct global: %s", v.LongString())
				}
				// Common case: just flow backwards.
				if len(v.Args) == 1 || len(v.Args) == 2 && v.Args[0] == v.Args[1] {
					// Note: 386 lowers Neq32 to (TESTL cond cond),
					v = v.Args[0]
					continue
				}
				v.Fatalf("write barrier control value has more than one argument: %s", v.LongString())
			}

			// Mark everything after the load unsafe.
			found := false
			for _, v := range decisionBlock.Values {
				if found {
					lv.unsafePoints.Set(int32(v.ID))
				}
				found = found || v == load
			}
			lv.unsafeBlocks.Set(int32(decisionBlock.ID))

			// Mark the write barrier on/off blocks as unsafe.
			for _, e := range decisionBlock.Succs {
				x := e.Block()
				if x == b {
					continue
				}
				for _, v := range x.Values {
					lv.unsafePoints.Set(int32(v.ID))
				}
				lv.unsafeBlocks.Set(int32(x.ID))
			}

			// Mark from the join point up to the WBend as unsafe.
			for _, v := range b.Values {
				if v.Op == ssa.OpWBend {
					break
				}
				lv.unsafePoints.Set(int32(v.ID))
			}
		}
	}
}

// Returns true for instructions that must have a stack map.
//
// This does not necessarily mean the instruction is a safe-point. In
// particular, call Values can have a stack map in case the callee
// grows the stack, but not themselves be a safe-point.
func (lv *liveness) hasStackMap(v *ssa.Value) bool {
	if !v.Op.IsCall() {
		return false
	}
	// wbZero and wbCopy are write barriers and
	// deeply non-preemptible. They are unsafe points and
	// hence should not have liveness maps.
	if sym, ok := v.Aux.(*ssa.AuxCall); ok && (sym.Fn == ir.Syms.WBZero || sym.Fn == ir.Syms.WBMove) {
		return false
	}
	return true
}

// Initializes the sets for solving the live variables. Visits all the
// instructions in each basic block to summarizes the information at each basic
// block
func (lv *liveness) prologue() {
	lv.initcache()

	for _, b := range lv.f.Blocks {
		be := lv.blockEffects(b)

		// Walk the block instructions backward and update the block
		// effects with the each prog effects.
		for j := len(b.Values) - 1; j >= 0; j-- {
			pos, e := lv.valueEffects(b.Values[j])
			if e&varkill != 0 {
				be.varkill.Set(pos)
				be.uevar.Unset(pos)
			}
			if e&uevar != 0 {
				be.uevar.Set(pos)
			}
		}
	}
}

// Solve the liveness dataflow equations.
func (lv *liveness) solve() {
	// These temporary bitvectors exist to avoid successive allocations and
	// frees within the loop.
	nvars := int32(len(lv.vars))
	newlivein := bitvec.New(nvars)
	newliveout := bitvec.New(nvars)

	// Walk blocks in postorder ordering. This improves convergence.
	po := lv.f.Postorder()

	// Iterate through the blocks in reverse round-robin fashion. A work
	// queue might be slightly faster. As is, the number of iterations is
	// so low that it hardly seems to be worth the complexity.

	for change := true; change; {
		change = false
		for _, b := range po {
			be := lv.blockEffects(b)

			newliveout.Clear()
			switch b.Kind {
			case ssa.BlockRet:
				for _, pos := range lv.cache.retuevar {
					newliveout.Set(pos)
				}
			case ssa.BlockRetJmp:
				for _, pos := range lv.cache.tailuevar {
					newliveout.Set(pos)
				}
			case ssa.BlockExit:
				// panic exit - nothing to do
			default:
				// A variable is live on output from this block
				// if it is live on input to some successor.
				//
				// out[b] = \bigcup_{s \in succ[b]} in[s]
				newliveout.Copy(lv.blockEffects(b.Succs[0].Block()).livein)
				for _, succ := range b.Succs[1:] {
					newliveout.Or(newliveout, lv.blockEffects(succ.Block()).livein)
				}
			}

			if !be.liveout.Eq(newliveout) {
				change = true
				be.liveout.Copy(newliveout)
			}

			// A variable is live on input to this block
			// if it is used by this block, or live on output from this block and
			// not set by the code in this block.
			//
			// in[b] = uevar[b] \cup (out[b] \setminus varkill[b])
			newlivein.AndNot(be.liveout, be.varkill)
			be.livein.Or(newlivein, be.uevar)
		}
	}
}

// Visits all instructions in a basic block and computes a bit vector of live
// variables at each safe point locations.
func (lv *liveness) epilogue() {
	nvars := int32(len(lv.vars))
	liveout := bitvec.New(nvars)
	livedefer := bitvec.New(nvars) // always-live variables

	// If there is a defer (that could recover), then all output
	// parameters are live all the time.  In addition, any locals
	// that are pointers to heap-allocated output parameters are
	// also always live (post-deferreturn code needs these
	// pointers to copy values back to the stack).
	// TODO: if the output parameter is heap-allocated, then we
	// don't need to keep the stack copy live?
	if lv.fn.HasDefer() {
		for i, n := range lv.vars {
			if n.Class == ir.PPARAMOUT {
				if n.IsOutputParamHeapAddr() {
					// Just to be paranoid.  Heap addresses are PAUTOs.
					base.Fatalf("variable %v both output param and heap output param", n)
				}
				if n.Heapaddr != nil {
					// If this variable moved to the heap, then
					// its stack copy is not live.
					continue
				}
				// Note: zeroing is handled by zeroResults in walk.go.
				livedefer.Set(int32(i))
			}
			if n.IsOutputParamHeapAddr() {
				// This variable will be overwritten early in the function
				// prologue (from the result of a mallocgc) but we need to
				// zero it in case that malloc causes a stack scan.
				n.SetNeedzero(true)
				livedefer.Set(int32(i))
			}
			if n.OpenDeferSlot() {
				// Open-coded defer args slots must be live
				// everywhere in a function, since a panic can
				// occur (almost) anywhere. Because it is live
				// everywhere, it must be zeroed on entry.
				livedefer.Set(int32(i))
				// It was already marked as Needzero when created.
				if !n.Needzero() {
					base.Fatalf("all pointer-containing defer arg slots should have Needzero set")
				}
			}
		}
	}

	// We must analyze the entry block first. The runtime assumes
	// the function entry map is index 0. Conveniently, layout
	// already ensured that the entry block is first.
	if lv.f.Entry != lv.f.Blocks[0] {
		lv.f.Fatalf("entry block must be first")
	}

	{
		// Reserve an entry for function entry.
		live := bitvec.New(nvars)
		lv.livevars = append(lv.livevars, live)
	}

	for _, b := range lv.f.Blocks {
		be := lv.blockEffects(b)

		// Walk forward through the basic block instructions and
		// allocate liveness maps for those instructions that need them.
		for _, v := range b.Values {
			if !lv.hasStackMap(v) {
				continue
			}

			live := bitvec.New(nvars)
			lv.livevars = append(lv.livevars, live)
		}

		// walk backward, construct maps at each safe point
		index := int32(len(lv.livevars) - 1)

		liveout.Copy(be.liveout)
		for i := len(b.Values) - 1; i >= 0; i-- {
			v := b.Values[i]

			if lv.hasStackMap(v) {
				// Found an interesting instruction, record the
				// corresponding liveness information.

				live := &lv.livevars[index]
				live.Or(*live, liveout)
				live.Or(*live, livedefer) // only for non-entry safe points
				index--
			}

			// Update liveness information.
			pos, e := lv.valueEffects(v)
			if e&varkill != 0 {
				liveout.Unset(pos)
			}
			if e&uevar != 0 {
				liveout.Set(pos)
			}
		}

		if b == lv.f.Entry {
			if index != 0 {
				base.Fatalf("bad index for entry point: %v", index)
			}

			// Check to make sure only input variables are live.
			for i, n := range lv.vars {
				if !liveout.Get(int32(i)) {
					continue
				}
				if n.Class == ir.PPARAM {
					continue // ok
				}
				base.FatalfAt(n.Pos(), "bad live variable at entry of %v: %L", lv.fn.Nname, n)
			}

			// Record live variables.
			live := &lv.livevars[index]
			live.Or(*live, liveout)
		}

		if lv.doClobber {
			lv.clobber(b)
		}

		// The liveness maps for this block are now complete. Compact them.
		lv.compact(b)
	}

	// If we have an open-coded deferreturn call, make a liveness map for it.
	if lv.fn.OpenCodedDeferDisallowed() {
		lv.livenessMap.DeferReturn = objw.StackMapDontCare
	} else {
		idx, _ := lv.stackMapSet.add(livedefer)
		lv.livenessMap.DeferReturn = objw.StackMapIndex(idx)
	}

	// Done compacting. Throw out the stack map set.
	lv.stackMaps = lv.stackMapSet.extractUnique()
	lv.stackMapSet = bvecSet{}

	// Useful sanity check: on entry to the function,
	// the only things that can possibly be live are the
	// input parameters.
	for j, n := range lv.vars {
		if n.Class != ir.PPARAM && lv.stackMaps[0].Get(int32(j)) {
			lv.f.Fatalf("%v %L recorded as live on entry", lv.fn.Nname, n)
		}
	}
}

// Compact coalesces identical bitmaps from lv.livevars into the sets
// lv.stackMapSet.
//
// Compact clears lv.livevars.
//
// There are actually two lists of bitmaps, one list for the local variables and one
// list for the function arguments. Both lists are indexed by the same PCDATA
// index, so the corresponding pairs must be considered together when
// merging duplicates. The argument bitmaps change much less often during
// function execution than the local variable bitmaps, so it is possible that
// we could introduce a separate PCDATA index for arguments vs locals and
// then compact the set of argument bitmaps separately from the set of
// local variable bitmaps. As of 2014-04-02, doing this to the godoc binary
// is actually a net loss: we save about 50k of argument bitmaps but the new
// PCDATA tables cost about 100k. So for now we keep using a single index for
// both bitmap lists.
func (lv *liveness) compact(b *ssa.Block) {
	pos := 0
	if b == lv.f.Entry {
		// Handle entry stack map.
		lv.stackMapSet.add(lv.livevars[0])
		pos++
	}
	for _, v := range b.Values {
		if lv.hasStackMap(v) {
			idx, _ := lv.stackMapSet.add(lv.livevars[pos])
			pos++
			lv.livenessMap.set(v, objw.StackMapIndex(idx))
		}
		if lv.allUnsafe || v.Op != ssa.OpClobber && lv.unsafePoints.Get(int32(v.ID)) {
			lv.livenessMap.setUnsafeVal(v)
		}
	}
	if lv.allUnsafe || lv.unsafeBlocks.Get(int32(b.ID)) {
		lv.livenessMap.setUnsafeBlock(b)
	}

	// Reset livevars.
	lv.livevars = lv.livevars[:0]
}

func (lv *liveness) enableClobber() {
	// The clobberdead experiment inserts code to clobber pointer slots in all
	// the dead variables (locals and args) at every synchronous safepoint.
	if !base.Flag.ClobberDead {
		return
	}
	if lv.fn.Pragma&ir.CgoUnsafeArgs != 0 {
		// C or assembly code uses the exact frame layout. Don't clobber.
		return
	}
	if len(lv.vars) > 10000 || len(lv.f.Blocks) > 10000 {
		// Be careful to avoid doing too much work.
		// Bail if >10000 variables or >10000 blocks.
		// Otherwise, giant functions make this experiment generate too much code.
		return
	}
	if lv.f.Name == "forkAndExecInChild" {
		// forkAndExecInChild calls vfork on some platforms.
		// The code we add here clobbers parts of the stack in the child.
		// When the parent resumes, it is using the same stack frame. But the
		// child has clobbered stack variables that the parent needs. Boom!
		// In particular, the sys argument gets clobbered.
		return
	}
	if lv.f.Name == "wbBufFlush" ||
		((lv.f.Name == "callReflect" || lv.f.Name == "callMethod") && lv.fn.ABIWrapper()) {
		// runtime.wbBufFlush must not modify its arguments. See the comments
		// in runtime/mwbbuf.go:wbBufFlush.
		//
		// reflect.callReflect and reflect.callMethod are called from special
		// functions makeFuncStub and methodValueCall. The runtime expects
		// that it can find the first argument (ctxt) at 0(SP) in makeFuncStub
		// and methodValueCall's frame (see runtime/traceback.go:getArgInfo).
		// Normally callReflect and callMethod already do not modify the
		// argument, and keep it alive. But the compiler-generated ABI wrappers
		// don't do that. Special case the wrappers to not clobber its arguments.
		lv.noClobberArgs = true
	}
	if h := os.Getenv("GOCLOBBERDEADHASH"); h != "" {
		// Clobber only functions where the hash of the function name matches a pattern.
		// Useful for binary searching for a miscompiled function.
		hstr := ""
		for _, b := range hash.Sum20([]byte(lv.f.Name)) {
			hstr += fmt.Sprintf("%08b", b)
		}
		if !strings.HasSuffix(hstr, h) {
			return
		}
		fmt.Printf("\t\t\tCLOBBERDEAD %s\n", lv.f.Name)
	}
	lv.doClobber = true
}

// Inserts code to clobber pointer slots in all the dead variables (locals and args)
// at every synchronous safepoint in b.
func (lv *liveness) clobber(b *ssa.Block) {
	// Copy block's values to a temporary.
	oldSched := append([]*ssa.Value{}, b.Values...)
	b.Values = b.Values[:0]
	idx := 0

	// Clobber pointer slots in all dead variables at entry.
	if b == lv.f.Entry {
		for len(oldSched) > 0 && len(oldSched[0].Args) == 0 {
			// Skip argless ops. We need to skip at least
			// the lowered ClosurePtr op, because it
			// really wants to be first. This will also
			// skip ops like InitMem and SP, which are ok.
			b.Values = append(b.Values, oldSched[0])
			oldSched = oldSched[1:]
		}
		clobber(lv, b, lv.livevars[0])
		idx++
	}

	// Copy values into schedule, adding clobbering around safepoints.
	for _, v := range oldSched {
		if !lv.hasStackMap(v) {
			b.Values = append(b.Values, v)
			continue
		}
		clobber(lv, b, lv.livevars[idx])
		b.Values = append(b.Values, v)
		idx++
	}
}

// clobber generates code to clobber pointer slots in all dead variables
// (those not marked in live). Clobbering instructions are added to the end
// of b.Values.
func clobber(lv *liveness, b *ssa.Block, live bitvec.BitVec) {
	for i, n := range lv.vars {
		if !live.Get(int32(i)) && !n.Addrtaken() && !n.OpenDeferSlot() && !n.IsOutputParamHeapAddr() {
			// Don't clobber stack objects (address-taken). They are
			// tracked dynamically.
			// Also don't clobber slots that are live for defers (see
			// the code setting livedefer in epilogue).
			if lv.noClobberArgs && n.Class == ir.PPARAM {
				continue
			}
			clobberVar(b, n)
		}
	}
}

// clobberVar generates code to trash the pointers in v.
// Clobbering instructions are added to the end of b.Values.
func clobberVar(b *ssa.Block, v *ir.Name) {
	clobberWalk(b, v, 0, v.Type())
}

// b = block to which we append instructions
// v = variable
// offset = offset of (sub-portion of) variable to clobber (in bytes)
// t = type of sub-portion of v.
func clobberWalk(b *ssa.Block, v *ir.Name, offset int64, t *types.Type) {
	if !t.HasPointers() {
		return
	}
	switch t.Kind() {
	case types.TPTR,
		types.TUNSAFEPTR,
		types.TFUNC,
		types.TCHAN,
		types.TMAP:
		clobberPtr(b, v, offset)

	case types.TSTRING:
		// struct { byte *str; int len; }
		clobberPtr(b, v, offset)

	case types.TINTER:
		// struct { Itab *tab; void *data; }
		// or, when isnilinter(t)==true:
		// struct { Type *type; void *data; }
		clobberPtr(b, v, offset)
		clobberPtr(b, v, offset+int64(types.PtrSize))

	case types.TSLICE:
		// struct { byte *array; int len; int cap; }
		clobberPtr(b, v, offset)

	case types.TARRAY:
		for i := int64(0); i < t.NumElem(); i++ {
			clobberWalk(b, v, offset+i*t.Elem().Size(), t.Elem())
		}

	case types.TSTRUCT:
		for _, t1 := range t.Fields() {
			clobberWalk(b, v, offset+t1.Offset, t1.Type)
		}

	default:
		base.Fatalf("clobberWalk: unexpected type, %v", t)
	}
}

// clobberPtr generates a clobber of the pointer at offset offset in v.
// The clobber instruction is added at the end of b.
func clobberPtr(b *ssa.Block, v *ir.Name, offset int64) {
	b.NewValue0IA(src.NoXPos, ssa.OpClobber, types.TypeVoid, offset, v)
}

func (lv *liveness) showlive(v *ssa.Value, live bitvec.BitVec) {
	if base.Flag.Live == 0 || ir.FuncName(lv.fn) == "init" || strings.HasPrefix(ir.FuncName(lv.fn), ".") {
		return
	}
	if lv.fn.Wrapper() || lv.fn.Dupok() {
		// Skip reporting liveness information for compiler-generated wrappers.
		return
	}
	if !(v == nil || v.Op.IsCall()) {
		// Historically we only printed this information at
		// calls. Keep doing so.
		return
	}
	if live.IsEmpty() {
		return
	}

	pos := lv.fn.Nname.Pos()
	if v != nil {
		pos = v.Pos
	}

	s := "live at "
	if v == nil {
		s += fmt.Sprintf("entry to %s:", ir.FuncName(lv.fn))
	} else if sym, ok := v.Aux.(*ssa.AuxCall); ok && sym.Fn != nil {
		fn := sym.Fn.Name
		if pos := strings.Index(fn, "."); pos >= 0 {
			fn = fn[pos+1:]
		}
		s += fmt.Sprintf("call to %s:", fn)
	} else {
		s += "indirect call:"
	}

	// Sort variable names for display. Variables aren't in any particular order, and
	// the order can change by architecture, particularly with differences in regabi.
	var names []string
	for j, n := range lv.vars {
		if live.Get(int32(j)) {
			names = append(names, n.Sym().Name)
		}
	}
	sort.Strings(names)
	for _, v := range names {
		s += " " + v
	}

	base.WarnfAt(pos, "%s", s)
}

func (lv *liveness) printbvec(printed bool, name string, live bitvec.BitVec) bool {
	if live.IsEmpty() {
		return printed
	}

	if !printed {
		fmt.Printf("\t")
	} else {
		fmt.Printf(" ")
	}
	fmt.Printf("%s=", name)

	comma := ""
	for i, n := range lv.vars {
		if !live.Get(int32(i)) {
			continue
		}
		fmt.Printf("%s%s", comma, n.Sym().Name)
		comma = ","
	}
	return true
}

// printeffect is like printbvec, but for valueEffects.
func (lv *liveness) printeffect(printed bool, name string, pos int32, x bool) bool {
	if !x {
		return printed
	}
	if !printed {
		fmt.Printf("\t")
	} else {
		fmt.Printf(" ")
	}
	fmt.Printf("%s=", name)
	if x {
		fmt.Printf("%s", lv.vars[pos].Sym().Name)
	}

	return true
}

// Prints the computed liveness information and inputs, for debugging.
// This format synthesizes the information used during the multiple passes
// into a single presentation.
func (lv *liveness) printDebug() {
	fmt.Printf("liveness: %s\n", ir.FuncName(lv.fn))

	for i, b := range lv.f.Blocks {
		if i > 0 {
			fmt.Printf("\n")
		}

		// bb#0 pred=1,2 succ=3,4
		fmt.Printf("bb#%d pred=", b.ID)
		for j, pred := range b.Preds {
			if j > 0 {
				fmt.Printf(",")
			}
			fmt.Printf("%d", pred.Block().ID)
		}
		fmt.Printf(" succ=")
		for j, succ := range b.Succs {
			if j > 0 {
				fmt.Printf(",")
			}
			fmt.Printf("%d", succ.Block().ID)
		}
		fmt.Printf("\n")

		be := lv.blockEffects(b)

		// initial settings
		printed := false
		printed = lv.printbvec(printed, "uevar", be.uevar)
		printed = lv.printbvec(printed, "livein", be.livein)
		if printed {
			fmt.Printf("\n")
		}

		// program listing, with individual effects listed

		if b == lv.f.Entry {
			live := lv.stackMaps[0]
			fmt.Printf("(%s) function entry\n", base.FmtPos(lv.fn.Nname.Pos()))
			fmt.Printf("\tlive=")
			printed = false
			for j, n := range lv.vars {
				if !live.Get(int32(j)) {
					continue
				}
				if printed {
					fmt.Printf(",")
				}
				fmt.Printf("%v", n)
				printed = true
			}
			fmt.Printf("\n")
		}

		for _, v := range b.Values {
			fmt.Printf("(%s) %v\n", base.FmtPos(v.Pos), v.LongString())

			pcdata := lv.livenessMap.Get(v)

			pos, effect := lv.valueEffects(v)
			printed = false
			printed = lv.printeffect(printed, "uevar", pos, effect&uevar != 0)
			printed = lv.printeffect(printed, "varkill", pos, effect&varkill != 0)
			if printed {
				fmt.Printf("\n")
			}

			if pcdata.StackMapValid() {
				fmt.Printf("\tlive=")
				printed = false
				if pcdata.StackMapValid() {
					live := lv.stackMaps[pcdata]
					for j, n := range lv.vars {
						if !live.Get(int32(j)) {
							continue
						}
						if printed {
							fmt.Printf(",")
						}
						fmt.Printf("%v", n)
						printed = true
					}
				}
				fmt.Printf("\n")
			}

			if lv.livenessMap.GetUnsafe(v) {
				fmt.Printf("\tunsafe-point\n")
			}
		}
		if lv.livenessMap.GetUnsafeBlock(b) {
			fmt.Printf("\tunsafe-block\n")
		}

		// bb bitsets
		fmt.Printf("end\n")
		printed = false
		printed = lv.printbvec(printed, "varkill", be.varkill)
		printed = lv.printbvec(printed, "liveout", be.liveout)
		if printed {
			fmt.Printf("\n")
		}
	}

	fmt.Printf("\n")
}

// Dumps a slice of bitmaps to a symbol as a sequence of uint32 values. The
// first word dumped is the total number of bitmaps. The second word is the
// length of the bitmaps. All bitmaps are assumed to be of equal length. The
// remaining bytes are the raw bitmaps.
func (lv *liveness) emit() (argsSym, liveSym *obj.LSym) {
	// Size args bitmaps to be just large enough to hold the largest pointer.
	// First, find the largest Xoffset node we care about.
	// (Nodes without pointers aren't in lv.vars; see ShouldTrack.)
	var maxArgNode *ir.Name
	for _, n := range lv.vars {
		switch n.Class {
		case ir.PPARAM, ir.PPARAMOUT:
			if !n.IsOutputParamInRegisters() {
				if maxArgNode == nil || n.FrameOffset() > maxArgNode.FrameOffset() {
					maxArgNode = n
				}
			}
		}
	}
	// Next, find the offset of the largest pointer in the largest node.
	var maxArgs int64
	if maxArgNode != nil {
		maxArgs = maxArgNode.FrameOffset() + types.PtrDataSize(maxArgNode.Type())
	}

	// Size locals bitmaps to be stkptrsize sized.
	// We cannot shrink them to only hold the largest pointer,
	// because their size is used to calculate the beginning
	// of the local variables frame.
	// Further discussion in https://golang.org/cl/104175.
	// TODO: consider trimming leading zeros.
	// This would require shifting all bitmaps.
	maxLocals := lv.stkptrsize

	// Temporary symbols for encoding bitmaps.
	var argsSymTmp, liveSymTmp obj.LSym

	args := bitvec.New(int32(maxArgs / int64(types.PtrSize)))
	aoff := objw.Uint32(&argsSymTmp, 0, uint32(len(lv.stackMaps))) // number of bitmaps
	aoff = objw.Uint32(&argsSymTmp, aoff, uint32(args.N))          // number of bits in each bitmap

	locals := bitvec.New(int32(maxLocals / int64(types.PtrSize)))
	loff := objw.Uint32(&liveSymTmp, 0, uint32(len(lv.stackMaps))) // number of bitmaps
	loff = objw.Uint32(&liveSymTmp, loff, uint32(locals.N))        // number of bits in each bitmap

	for _, live := range lv.stackMaps {
		args.Clear()
		locals.Clear()

		lv.pointerMap(live, lv.vars, args, locals)

		aoff = objw.BitVec(&argsSymTmp, aoff, args)
		loff = objw.BitVec(&liveSymTmp, loff, locals)
	}

	// These symbols will be added to Ctxt.Data by addGCLocals
	// after parallel compilation is done.
	return base.Ctxt.GCLocalsSym(argsSymTmp.P), base.Ctxt.GCLocalsSym(liveSymTmp.P)
}

// Entry pointer for Compute analysis. Solves for the Compute of
// pointer variables in the function and emits a runtime data
// structure read by the garbage collector.
// Returns a map from GC safe points to their corresponding stack map index,
// and a map that contains all input parameters that may be partially live.
func Compute(curfn *ir.Func, f *ssa.Func, stkptrsize int64, pp *objw.Progs) (Map, map[*ir.Name]bool) {
	// Construct the global liveness state.
	vars, idx := getvariables(curfn)
	lv := newliveness(curfn, f, vars, idx, stkptrsize)

	// Run the dataflow framework.
	lv.prologue()
	lv.solve()
	lv.epilogue()
	if base.Flag.Live > 0 {
		lv.showlive(nil, lv.stackMaps[0])
		for _, b := range f.Blocks {
			for _, val := range b.Values {
				if idx := lv.livenessMap.Get(val); idx.StackMapValid() {
					lv.showlive(val, lv.stackMaps[idx])
				}
			}
		}
	}
	if base.Flag.Live >= 2 {
		lv.printDebug()
	}

	// Update the function cache.
	{
		cache := f.Cache.Liveness.(*livenessFuncCache)
		if cap(lv.be) < 2000 { // Threshold from ssa.Cache slices.
			for i := range lv.be {
				lv.be[i] = blockEffects{}
			}
			cache.be = lv.be
		}
		if len(lv.livenessMap.Vals) < 2000 {
			cache.livenessMap = lv.livenessMap
		}
	}

	// Emit the live pointer map data structures
	ls := curfn.LSym
	fninfo := ls.Func()
	fninfo.GCArgs, fninfo.GCLocals = lv.emit()

	p := pp.Prog(obj.AFUNCDATA)
	p.From.SetConst(rtabi.FUNCDATA_ArgsPointerMaps)
	p.To.Type = obj.TYPE_MEM
	p.To.Name = obj.NAME_EXTERN
	p.To.Sym = fninfo.GCArgs

	p = pp.Prog(obj.AFUNCDATA)
	p.From.SetConst(rtabi.FUNCDATA_LocalsPointerMaps)
	p.To.Type = obj.TYPE_MEM
	p.To.Name = obj.NAME_EXTERN
	p.To.Sym = fninfo.GCLocals

	if x := lv.emitStackObjects(); x != nil {
		p := pp.Prog(obj.AFUNCDATA)
		p.From.SetConst(rtabi.FUNCDATA_StackObjects)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = x
	}

	return lv.livenessMap, lv.partLiveArgs
}

func (lv *liveness) emitStackObjects() *obj.LSym {
	var vars []*ir.Name
	for _, n := range lv.fn.Dcl {
		if shouldTrack(n) && n.Addrtaken() && n.Esc() != ir.EscHeap {
			vars = append(vars, n)
		}
	}
	if len(vars) == 0 {
		return nil
	}

	// Sort variables from lowest to highest address.
	slices.SortFunc(vars, func(a, b *ir.Name) int { return cmp.Compare(a.FrameOffset(), b.FrameOffset()) })

	// Populate the stack object data.
	// Format must match runtime/stack.go:stackObjectRecord.
	x := base.Ctxt.Lookup(lv.fn.LSym.Name + ".stkobj")
	x.Set(obj.AttrContentAddressable, true)
	lv.fn.LSym.Func().StackObjects = x
	off := 0
	off = objw.Uintptr(x, off, uint64(len(vars)))
	for _, v := range vars {
		// Note: arguments and return values have non-negative Xoffset,
		// in which case the offset is relative to argp.
		// Locals have a negative Xoffset, in which case the offset is relative to varp.
		// We already limit the frame size, so the offset and the object size
		// should not be too big.
		frameOffset := v.FrameOffset()
		if frameOffset != int64(int32(frameOffset)) {
			base.Fatalf("frame offset too big: %v %d", v, frameOffset)
		}
		off = objw.Uint32(x, off, uint32(frameOffset))

		t := v.Type()
		sz := t.Size()
		if sz != int64(int32(sz)) {
			base.Fatalf("stack object too big: %v of type %v, size %d", v, t, sz)
		}
		lsym, ptrBytes := reflectdata.GCSym(t)
		off = objw.Uint32(x, off, uint32(sz))
		off = objw.Uint32(x, off, uint32(ptrBytes))
		off = objw.SymPtrOff(x, off, lsym)
	}

	if base.Flag.Live != 0 {
		for _, v := range vars {
			base.WarnfAt(v.Pos(), "stack object %v %v", v, v.Type())
		}
	}

	return x
}

// isfat reports whether a variable of type t needs multiple assignments to initialize.
// For example:
//
//	type T struct { x, y int }
//	x := T{x: 0, y: 1}
//
// Then we need:
//
//	var t T
//	t.x = 0
//	t.y = 1
//
// to fully initialize t.
func isfat(t *types.Type) bool {
	if t != nil {
		switch t.Kind() {
		case types.TSLICE, types.TSTRING,
			types.TINTER: // maybe remove later
			return true
		case types.TARRAY:
			// Array of 1 element, check if element is fat
			if t.NumElem() == 1 {
				return isfat(t.Elem())
			}
			return true
		case types.TSTRUCT:
			// Struct with 1 field, check if field is fat
			if t.NumFields() == 1 {
				return isfat(t.Field(0).Type)
			}
			return true
		}
	}

	return false
}

// WriteFuncMap writes the pointer bitmaps for bodyless function fn's
// inputs and outputs as the value of symbol <fn>.args_stackmap.
// If fn has outputs, two bitmaps are written, otherwise just one.
func WriteFuncMap(fn *ir.Func, abiInfo *abi.ABIParamResultInfo) {
	if ir.FuncName(fn) == "_" {
		return
	}
	nptr := int(abiInfo.ArgWidth() / int64(types.PtrSize))
	bv := bitvec.New(int32(nptr))

	for _, p := range abiInfo.InParams() {
		typebits.SetNoCheck(p.Type, p.FrameOffset(abiInfo), bv)
	}

	nbitmap := 1
	if fn.Type().NumResults() > 0 {
		nbitmap = 2
	}
	lsym := base.Ctxt.Lookup(fn.LSym.Name + ".args_stackmap")
	lsym.Set(obj.AttrLinkname, true) // allow args_stackmap referenced from assembly
	off := objw.Uint32(lsym, 0, uint32(nbitmap))
	off = objw.Uint32(lsym, off, uint32(bv.N))
	off = objw.BitVec(lsym, off, bv)

	if fn.Type().NumResults() > 0 {
		for _, p := range abiInfo.OutParams() {
			if len(p.Registers) == 0 {
				typebits.SetNoCheck(p.Type, p.FrameOffset(abiInfo), bv)
			}
		}
		off = objw.BitVec(lsym, off, bv)
	}

	objw.Global(lsym, int32(off), obj.RODATA|obj.LOCAL)
}

"""



```