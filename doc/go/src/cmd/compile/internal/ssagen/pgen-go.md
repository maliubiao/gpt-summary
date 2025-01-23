Response: Let's break down the thought process for analyzing the provided Go code.

**1. Initial Skim and Keywords:**

First, I'd quickly skim the code, looking for recognizable keywords and patterns. Things that jump out:

* `package ssagen`: This immediately tells us it's part of the SSA generation phase of the Go compiler.
* `import`:  A standard Go import section, hinting at dependencies on other compiler internals (`cmd/compile/internal/...`).
* Function names like `cmpstackvarlt`, `needAlloc`, `AllocFrame`, `Compile`, `StackOffset`, `fieldtrack`, `CheckLargeStacks`. These are good indicators of the module's responsibilities.
* Data structures like `largeStack`, suggesting some form of monitoring or error handling related to stack sizes.
* Comments: The copyright notice and the detailed comments explaining individual functions are invaluable.

**2. Focus on Core Functionality:**

Next, I'd focus on the functions that seem central to the module's purpose. `Compile` looks like a high-level entry point, as it mentions "builds an SSA backend function" and "generates a plist" (presumably for instruction emission). `AllocFrame` clearly deals with stack frame allocation. `cmpstackvarlt` stands out as a comparison function, likely used for sorting.

**3. Deconstructing Key Functions:**

* **`cmpstackvarlt`:** The comments are very detailed here. I'd note the different sorting criteria: non-autos before autos, frame offset for non-autos, used before unused, pointer types before non-pointer, need-zeroing grouping, alignment, open-coded defer slots. This tells me a lot about how the compiler optimizes stack layout.

* **`needAlloc`:**  This is simpler. It determines if a variable needs stack space allocated in the current frame, distinguishing between local variables and function parameters/results.

* **`AllocFrame`:** This function is more complex. I'd break it down step by step:
    * Initialization (`s.stksize`, `s.stkptrsize`, `s.stkalign`).
    * Marking unused `PAUTO` variables.
    * Marking used variables based on SSA `RegAlloc` and value usage.
    * Handling `MergeLocals` for potential stack slot reuse. This is a key optimization.
    * Sorting `fn.Dcl` (declarations) using `cmpstackvarlt`. The "stable" sort is important for consistent output.
    * Rewriting `fn.Dcl` to group followers after leaders in the `MergeLocals` scenario.
    * Iterating through the sorted declarations and assigning stack offsets. Important considerations: padding for zero-sized objects, alignment, tracking pointer-containing objects.
    * Handling follower offsets in the `MergeLocals` case.
    * Final rounding up of `stksize` and `stkptrsize`.

* **`Compile`:** This seems like the main orchestrator:
    * Calls `buildssa` (not in the provided code, but we can infer it builds the SSA representation).
    * Checks for excessively large stack frames *before* and *after* `genssa`.
    * Creates `objw.Progs` for generating machine code.
    * Calls `genssa` (presumably generates assembly code from the SSA).
    * Calls `pp.Flush()` to assemble.
    * Handles weak relocations for global map initialization in package init functions.
    * Calls `fieldtrack`.

* **`StackOffset`:**  Calculates the DWARF stack offset, accounting for fixed frame size and frame pointers.

* **`fieldtrack`:** Adds relocations to track struct field usage for potential optimizations or debugging.

* **`CheckLargeStacks`:**  Reports errors if any functions have excessively large stack frames.

**4. Inferring Go Feature Implementation:**

Based on the function names and logic, I can infer that `pgen.go` is heavily involved in:

* **Stack Frame Allocation:**  `AllocFrame` is the primary function for this. It determines the size and layout of the stack frame for a function.
* **Local Variable Management:**  Tracking used/unused variables, assigning offsets, and the `MergeLocals` optimization are key aspects.
* **Code Generation (Indirectly):** While `genssa` isn't shown, the context within `Compile` suggests its role in translating SSA to machine code instructions.
* **Optimization:**  `MergeLocals` is a clear optimization. The sorting in `cmpstackvarlt` also hints at optimizations related to GC and memory layout.
* **Debugging Information:** `StackOffset` is specifically for DWARF debugging information.

**5. Generating Go Code Examples (with Assumptions):**

To provide concrete examples, I need to make some assumptions about how the compiler uses this code.

* **Stack Allocation:** I can demonstrate local variable allocation and how the compiler might assign offsets.
* **Merge Locals:** I'd need an example where two variables have non-overlapping lifetimes and can share the same stack space.
* **Parameter/Result Handling:**  Illustrating the difference between `PAUTO`, `PPARAM`, and `PPARAMOUT` would be helpful.

**6. Command Line Arguments (Inference):**

The code mentions `base.Debug.MergeLocals` and related flags. I would infer that these are likely controlled by `-gcflags` or similar command-line options passed to the `go build` command. I'd look for patterns in how these flags are used (e.g., checking for non-zero values).

**7. Common Mistakes (Reasoning):**

I'd think about potential pitfalls related to stack management:

* **Large Stack Frames:** The `CheckLargeStacks` function itself highlights this. Recursive functions or functions with many large local variables are candidates.
* **Incorrectly Assuming Stack Layout:**  Developers shouldn't rely on specific stack layouts, as the compiler can reorder variables for optimization.

**8. Refining and Organizing the Output:**

Finally, I'd organize the information logically, starting with a summary of the file's purpose, then detailing the functionality of key functions, providing code examples, discussing command-line arguments, and addressing potential mistakes. I'd use clear headings and bullet points to improve readability.

This detailed thought process, combining code analysis, keyword identification, and logical inference, allows for a comprehensive understanding of the provided Go compiler code snippet.
`go/src/cmd/compile/internal/ssagen/pgen.go` 是 Go 语言编译器中 SSA (Static Single Assignment) 代码生成阶段的一个关键文件。它的主要功能是：**将经过 SSA 优化的中间表示转换为目标机器的指令序列 (plan9 assembly - plist)。**

更具体地说，`pgen.go` 负责以下几个核心任务：

1. **栈帧分配 (Stack Frame Allocation):**
   - 确定函数局部变量所需的栈空间大小 (`AllocFrame` 函数)。
   - 计算每个局部变量在栈帧中的偏移量。
   - 考虑变量的生命周期（通过 `liveness` 包进行分析），可以将生命周期不重叠的变量分配到相同的栈空间，以优化栈空间利用率 (`MergeLocals` 功能)。
   - 根据变量的类型、大小、对齐要求等进行排序，以便更有效地分配栈空间，并提高 GC 的效率。
   - 区分需要初始化的变量 (`Needzero`)。

2. **SSA 到 Plan 9 汇编的转换 (`genssa` 函数，虽然代码中未直接展示，但 `Compile` 函数调用了它):**
   - 将 SSA 的操作 (operations) 转换为目标架构的指令。
   - 处理函数调用、返回值、控制流等。
   - 生成用于调试的元数据。

3. **生成 `plist` (Plan 9 assembly list):**
   - `objw.Progs` 用于构建最终的汇编代码。
   - `pp.Flush()` 将生成的汇编代码写入到目标文件中。

4. **处理与栈相关的操作:**
   - 计算局部变量相对于栈指针的偏移量 (`StackOffset` 函数)。

5. **处理函数编译的入口 (`Compile` 函数):**
   - 构建 SSA 表示 (`buildssa` 函数，代码中未展示)。
   - 调用 `AllocFrame` 进行栈帧分配。
   - 调用 `genssa` 进行 SSA 到汇编的转换。
   - 检查栈帧大小是否超过限制。
   - 处理包初始化函数的特殊逻辑 (弱化全局 map 初始化相关的重定位)。
   - 记录使用的结构体字段 (`fieldtrack` 函数)。

**它是什么 Go 语言功能的实现？**

`pgen.go` 是 Go 语言编译器将 Go 源代码编译成可执行机器码的核心组成部分。它直接参与了：

* **函数调用机制:** 栈帧的布局直接影响函数调用的参数传递、局部变量访问和返回值的处理。
* **变量的内存分配:**  `AllocFrame` 负责为局部变量在栈上分配空间。
* **垃圾回收 (GC):**  变量的排序和 `stkptrsize` 的计算对于 GC 扫描栈上的指针至关重要。
* **调试信息生成:** `StackOffset` 用于生成 DWARF 调试信息，方便调试器定位变量。
* **性能优化:** `MergeLocals` 是一种优化栈空间使用的技术。

**Go 代码示例 (假设):**

假设我们有以下简单的 Go 函数：

```go
package main

func add(a, b int) int {
	x := a + b
	y := 10
	return x + y
}

func main() {
	result := add(5, 3)
	println(result)
}
```

当编译器编译 `add` 函数时，`pgen.go` 的 `AllocFrame` 函数可能会执行以下操作（这是一个简化的例子，实际情况更复杂）：

**假设的输入 (fn.Dcl):**

`fn.Dcl` 包含了 `add` 函数的声明信息，可能如下所示（简化表示）：

```
[
  &ir.Name{Sym: "a", Class: ir.PPARAM, Type: int},
  &ir.Name{Sym: "b", Class: ir.PPARAM, Type: int},
  &ir.Name{Sym: "x", Class: ir.PAUTO, Type: int},
  &ir.Name{Sym: "y", Class: ir.PAUTO, Type: int},
  &ir.Name{Sym: "", Class: ir.PPARAMOUT, Type: int}, // 返回值
]
```

**假设的输出 (经过 `AllocFrame` 后):**

```
// 假设 int 类型大小为 8 字节，对齐为 8 字节
s.stksize = 16 // x 和 y 各占 8 字节
s.stkptrsize = 0 // 没有指针类型的局部变量
s.stkalign = 8

// 更新后的 fn.Dcl (部分)
&ir.Name{Sym: "x", Class: ir.PAUTO, Type: int, FrameOffset: -8},
&ir.Name{Sym: "y", Class: ir.PAUTO, Type: int, FrameOffset: -16},
```

在这个例子中，`AllocFrame` 计算出局部变量 `x` 和 `y` 需要 16 字节的栈空间。`x` 被分配到相对于栈底 -8 字节的位置，`y` 被分配到 -16 字节的位置。变量的排序可能受到 `cmpstackvarlt` 函数的逻辑影响，例如，是否 `x` 比 `y` 更早被使用。

**代码推理:**

`cmpstackvarlt` 函数的逻辑很复杂，它定义了局部变量在栈帧中的排序规则。 它的目标是优化栈的布局，例如：

- 将非自动变量（参数、返回值）放在前面，因为它们的偏移量由 ABI 确定。
- 将被使用的变量放在前面，允许截断未使用的变量。
- 将指针类型的变量放在一起，有助于 GC 效率。
- 将需要零初始化的变量放在一起，方便批量初始化。
- 根据对齐方式降序排列，提高内存利用率。

`needAlloc` 函数区分了哪些变量需要在当前函数的栈帧中分配空间。参数和返回值通常在调用者的栈帧中，而局部变量需要在当前函数的栈帧中分配。

`AllocFrame` 中的 `MergeLocals` 功能尝试将生命周期不重叠的局部变量分配到相同的栈空间。这可以通过 `liveness.MergeLocals` 分析得到。

**命令行参数的具体处理:**

代码中涉及的命令行参数主要是通过 `base.Debug` 来访问的调试标志，例如 `base.Debug.MergeLocals` 和 `base.Debug.MergeLocalsTrace`。 这些标志通常通过 `-gcflags` 传递给 `go build` 命令。

例如，要启用 `MergeLocals` 的详细跟踪信息，可以使用以下命令编译 Go 代码：

```bash
go build -gcflags="-d=m=2" your_program.go
```

这里 `-gcflags` 将 `-d=m=2` 传递给 Go 编译器，其中 `m` 对应 `MergeLocals`，`2` 表示跟踪级别。

**使用者易犯错的点:**

由于 `pgen.go` 是编译器内部实现，普通 Go 开发者不会直接与之交互，因此不容易犯错。 然而，了解其背后的逻辑可以帮助理解一些性能相关的行为：

* **过度使用局部变量:**  虽然现代计算机的内存通常很充足，但过多的局部变量仍然会增加栈帧大小，可能导致栈溢出或降低性能。编译器会尽力优化，但开发者也应该注意。
* **依赖特定的栈布局:**  开发者**绝对不应该**依赖局部变量在栈上的特定布局。编译器的优化可能会改变布局，导致程序行为不可预测。编译器保留对栈布局进行优化的权利。

**总结:**

`go/src/cmd/compile/internal/ssagen/pgen.go` 是 Go 语言编译器中负责将 SSA 中间表示转换为目标机器汇编代码的关键组件。它处理栈帧分配、局部变量布局、并进行一些优化以提高性能和 GC 效率。 理解其功能有助于理解 Go 程序的底层执行机制，尽管开发者通常不需要直接与其交互。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssagen/pgen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssagen

import (
	"fmt"
	"internal/buildcfg"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"

	"cmd/compile/internal/base"
	"cmd/compile/internal/inline"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/liveness"
	"cmd/compile/internal/objw"
	"cmd/compile/internal/pgoir"
	"cmd/compile/internal/ssa"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/internal/src"
)

// cmpstackvarlt reports whether the stack variable a sorts before b.
func cmpstackvarlt(a, b *ir.Name, mls *liveness.MergeLocalsState) bool {
	// Sort non-autos before autos.
	if needAlloc(a) != needAlloc(b) {
		return needAlloc(b)
	}

	// If both are non-auto (e.g., parameters, results), then sort by
	// frame offset (defined by ABI).
	if !needAlloc(a) {
		return a.FrameOffset() < b.FrameOffset()
	}

	// From here on, a and b are both autos (i.e., local variables).

	// Sort followers after leaders, if mls != nil
	if mls != nil {
		aFollow := mls.Subsumed(a)
		bFollow := mls.Subsumed(b)
		if aFollow != bFollow {
			return bFollow
		}
	}

	// Sort used before unused (so AllocFrame can truncate unused
	// variables).
	if a.Used() != b.Used() {
		return a.Used()
	}

	// Sort pointer-typed before non-pointer types.
	// Keeps the stack's GC bitmap compact.
	ap := a.Type().HasPointers()
	bp := b.Type().HasPointers()
	if ap != bp {
		return ap
	}

	// Group variables that need zeroing, so we can efficiently zero
	// them altogether.
	ap = a.Needzero()
	bp = b.Needzero()
	if ap != bp {
		return ap
	}

	// Sort variables in descending alignment order, so we can optimally
	// pack variables into the frame.
	if a.Type().Alignment() != b.Type().Alignment() {
		return a.Type().Alignment() > b.Type().Alignment()
	}

	// Sort normal variables before open-coded-defer slots, so that the
	// latter are grouped together and near the top of the frame (to
	// minimize varint encoding of their varp offset).
	if a.OpenDeferSlot() != b.OpenDeferSlot() {
		return a.OpenDeferSlot()
	}

	// If a and b are both open-coded defer slots, then order them by
	// index in descending order, so they'll be laid out in the frame in
	// ascending order.
	//
	// Their index was saved in FrameOffset in state.openDeferSave.
	if a.OpenDeferSlot() {
		return a.FrameOffset() > b.FrameOffset()
	}

	// Tie breaker for stable results.
	return a.Sym().Name < b.Sym().Name
}

// needAlloc reports whether n is within the current frame, for which we need to
// allocate space. In particular, it excludes arguments and results, which are in
// the callers frame.
func needAlloc(n *ir.Name) bool {
	if n.Op() != ir.ONAME {
		base.FatalfAt(n.Pos(), "%v has unexpected Op %v", n, n.Op())
	}

	switch n.Class {
	case ir.PAUTO:
		return true
	case ir.PPARAM:
		return false
	case ir.PPARAMOUT:
		return n.IsOutputParamInRegisters()

	default:
		base.FatalfAt(n.Pos(), "%v has unexpected Class %v", n, n.Class)
		return false
	}
}

func (s *ssafn) AllocFrame(f *ssa.Func) {
	s.stksize = 0
	s.stkptrsize = 0
	s.stkalign = int64(types.RegSize)
	fn := s.curfn

	// Mark the PAUTO's unused.
	for _, ln := range fn.Dcl {
		if ln.OpenDeferSlot() {
			// Open-coded defer slots have indices that were assigned
			// upfront during SSA construction, but the defer statement can
			// later get removed during deadcode elimination (#61895). To
			// keep their relative offsets correct, treat them all as used.
			continue
		}

		if needAlloc(ln) {
			ln.SetUsed(false)
		}
	}

	for _, l := range f.RegAlloc {
		if ls, ok := l.(ssa.LocalSlot); ok {
			ls.N.SetUsed(true)
		}
	}

	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if n, ok := v.Aux.(*ir.Name); ok {
				switch n.Class {
				case ir.PPARAMOUT:
					if n.IsOutputParamInRegisters() && v.Op == ssa.OpVarDef {
						// ignore VarDef, look for "real" uses.
						// TODO: maybe do this for PAUTO as well?
						continue
					}
					fallthrough
				case ir.PPARAM, ir.PAUTO:
					n.SetUsed(true)
				}
			}
		}
	}

	var mls *liveness.MergeLocalsState
	var leaders map[*ir.Name]int64
	if base.Debug.MergeLocals != 0 {
		mls = liveness.MergeLocals(fn, f)
		if base.Debug.MergeLocalsTrace > 0 && mls != nil {
			savedNP, savedP := mls.EstSavings()
			fmt.Fprintf(os.Stderr, "%s: %d bytes of stack space saved via stack slot merging (%d nonpointer %d pointer)\n", ir.FuncName(fn), savedNP+savedP, savedNP, savedP)
			if base.Debug.MergeLocalsTrace > 1 {
				fmt.Fprintf(os.Stderr, "=-= merge locals state for %v:\n%v",
					fn, mls)
			}
		}
		leaders = make(map[*ir.Name]int64)
	}

	// Use sort.SliceStable instead of sort.Slice so stack layout (and thus
	// compiler output) is less sensitive to frontend changes that
	// introduce or remove unused variables.
	sort.SliceStable(fn.Dcl, func(i, j int) bool {
		return cmpstackvarlt(fn.Dcl[i], fn.Dcl[j], mls)
	})

	if mls != nil {
		// Rewrite fn.Dcl to reposition followers (subsumed vars) to
		// be immediately following the leader var in their partition.
		followers := []*ir.Name{}
		newdcl := make([]*ir.Name, 0, len(fn.Dcl))
		for i := 0; i < len(fn.Dcl); i++ {
			n := fn.Dcl[i]
			if mls.Subsumed(n) {
				continue
			}
			newdcl = append(newdcl, n)
			if mls.IsLeader(n) {
				followers = mls.Followers(n, followers)
				// position followers immediately after leader
				newdcl = append(newdcl, followers...)
			}
		}
		fn.Dcl = newdcl
	}

	if base.Debug.MergeLocalsTrace > 1 && mls != nil {
		fmt.Fprintf(os.Stderr, "=-= sorted DCL for %v:\n", fn)
		for i, v := range fn.Dcl {
			if !ssa.IsMergeCandidate(v) {
				continue
			}
			fmt.Fprintf(os.Stderr, " %d: %q isleader=%v subsumed=%v used=%v sz=%d align=%d t=%s\n", i, v.Sym().Name, mls.IsLeader(v), mls.Subsumed(v), v.Used(), v.Type().Size(), v.Type().Alignment(), v.Type().String())
		}
	}

	// Reassign stack offsets of the locals that are used.
	lastHasPtr := false
	for i, n := range fn.Dcl {
		if n.Op() != ir.ONAME || n.Class != ir.PAUTO && !(n.Class == ir.PPARAMOUT && n.IsOutputParamInRegisters()) {
			// i.e., stack assign if AUTO, or if PARAMOUT in registers (which has no predefined spill locations)
			continue
		}
		if mls != nil && mls.Subsumed(n) {
			continue
		}
		if !n.Used() {
			fn.DebugInfo.(*ssa.FuncDebug).OptDcl = fn.Dcl[i:]
			fn.Dcl = fn.Dcl[:i]
			break
		}
		types.CalcSize(n.Type())
		w := n.Type().Size()
		if w >= types.MaxWidth || w < 0 {
			base.Fatalf("bad width")
		}
		if w == 0 && lastHasPtr {
			// Pad between a pointer-containing object and a zero-sized object.
			// This prevents a pointer to the zero-sized object from being interpreted
			// as a pointer to the pointer-containing object (and causing it
			// to be scanned when it shouldn't be). See issue 24993.
			w = 1
		}
		s.stksize += w
		s.stksize = types.RoundUp(s.stksize, n.Type().Alignment())
		if n.Type().Alignment() > int64(types.RegSize) {
			s.stkalign = n.Type().Alignment()
		}
		if n.Type().HasPointers() {
			s.stkptrsize = s.stksize
			lastHasPtr = true
		} else {
			lastHasPtr = false
		}
		n.SetFrameOffset(-s.stksize)
		if mls != nil && mls.IsLeader(n) {
			leaders[n] = -s.stksize
		}
	}

	if mls != nil {
		// Update offsets of followers (subsumed vars) to be the
		// same as the leader var in their partition.
		for i := 0; i < len(fn.Dcl); i++ {
			n := fn.Dcl[i]
			if !mls.Subsumed(n) {
				continue
			}
			leader := mls.Leader(n)
			off, ok := leaders[leader]
			if !ok {
				panic("internal error missing leader")
			}
			// Set the stack offset this subsumed (followed) var
			// to be the same as the leader.
			n.SetFrameOffset(off)
		}

		if base.Debug.MergeLocalsTrace > 1 {
			fmt.Fprintf(os.Stderr, "=-= stack layout for %v:\n", fn)
			for i, v := range fn.Dcl {
				if v.Op() != ir.ONAME || (v.Class != ir.PAUTO && !(v.Class == ir.PPARAMOUT && v.IsOutputParamInRegisters())) {
					continue
				}
				fmt.Fprintf(os.Stderr, " %d: %q frameoff %d isleader=%v subsumed=%v sz=%d align=%d t=%s\n", i, v.Sym().Name, v.FrameOffset(), mls.IsLeader(v), mls.Subsumed(v), v.Type().Size(), v.Type().Alignment(), v.Type().String())
			}
		}
	}

	s.stksize = types.RoundUp(s.stksize, s.stkalign)
	s.stkptrsize = types.RoundUp(s.stkptrsize, s.stkalign)
}

const maxStackSize = 1 << 30

// Compile builds an SSA backend function,
// uses it to generate a plist,
// and flushes that plist to machine code.
// worker indicates which of the backend workers is doing the processing.
func Compile(fn *ir.Func, worker int, profile *pgoir.Profile) {
	f := buildssa(fn, worker, inline.IsPgoHotFunc(fn, profile) || inline.HasPgoHotInline(fn))
	// Note: check arg size to fix issue 25507.
	if f.Frontend().(*ssafn).stksize >= maxStackSize || f.OwnAux.ArgWidth() >= maxStackSize {
		largeStackFramesMu.Lock()
		largeStackFrames = append(largeStackFrames, largeStack{locals: f.Frontend().(*ssafn).stksize, args: f.OwnAux.ArgWidth(), pos: fn.Pos()})
		largeStackFramesMu.Unlock()
		return
	}
	pp := objw.NewProgs(fn, worker)
	defer pp.Free()
	genssa(f, pp)
	// Check frame size again.
	// The check above included only the space needed for local variables.
	// After genssa, the space needed includes local variables and the callee arg region.
	// We must do this check prior to calling pp.Flush.
	// If there are any oversized stack frames,
	// the assembler may emit inscrutable complaints about invalid instructions.
	if pp.Text.To.Offset >= maxStackSize {
		largeStackFramesMu.Lock()
		locals := f.Frontend().(*ssafn).stksize
		largeStackFrames = append(largeStackFrames, largeStack{locals: locals, args: f.OwnAux.ArgWidth(), callee: pp.Text.To.Offset - locals, pos: fn.Pos()})
		largeStackFramesMu.Unlock()
		return
	}

	pp.Flush() // assemble, fill in boilerplate, etc.

	// If we're compiling the package init function, search for any
	// relocations that target global map init outline functions and
	// turn them into weak relocs.
	if fn.IsPackageInit() && base.Debug.WrapGlobalMapCtl != 1 {
		weakenGlobalMapInitRelocs(fn)
	}

	// fieldtrack must be called after pp.Flush. See issue 20014.
	fieldtrack(pp.Text.From.Sym, fn.FieldTrack)
}

// globalMapInitLsyms records the LSym of each map.init.NNN outlined
// map initializer function created by the compiler.
var globalMapInitLsyms map[*obj.LSym]struct{}

// RegisterMapInitLsym records "s" in the set of outlined map initializer
// functions.
func RegisterMapInitLsym(s *obj.LSym) {
	if globalMapInitLsyms == nil {
		globalMapInitLsyms = make(map[*obj.LSym]struct{})
	}
	globalMapInitLsyms[s] = struct{}{}
}

// weakenGlobalMapInitRelocs walks through all of the relocations on a
// given a package init function "fn" and looks for relocs that target
// outlined global map initializer functions; if it finds any such
// relocs, it flags them as R_WEAK.
func weakenGlobalMapInitRelocs(fn *ir.Func) {
	if globalMapInitLsyms == nil {
		return
	}
	for i := range fn.LSym.R {
		tgt := fn.LSym.R[i].Sym
		if tgt == nil {
			continue
		}
		if _, ok := globalMapInitLsyms[tgt]; !ok {
			continue
		}
		if base.Debug.WrapGlobalMapDbg > 1 {
			fmt.Fprintf(os.Stderr, "=-= weakify fn %v reloc %d %+v\n", fn, i,
				fn.LSym.R[i])
		}
		// set the R_WEAK bit, leave rest of reloc type intact
		fn.LSym.R[i].Type |= objabi.R_WEAK
	}
}

// StackOffset returns the stack location of a LocalSlot relative to the
// stack pointer, suitable for use in a DWARF location entry. This has nothing
// to do with its offset in the user variable.
func StackOffset(slot ssa.LocalSlot) int32 {
	n := slot.N
	var off int64
	switch n.Class {
	case ir.PPARAM, ir.PPARAMOUT:
		if !n.IsOutputParamInRegisters() {
			off = n.FrameOffset() + base.Ctxt.Arch.FixedFrameSize
			break
		}
		fallthrough // PPARAMOUT in registers allocates like an AUTO
	case ir.PAUTO:
		off = n.FrameOffset()
		if base.Ctxt.Arch.FixedFrameSize == 0 {
			off -= int64(types.PtrSize)
		}
		if buildcfg.FramePointerEnabled {
			off -= int64(types.PtrSize)
		}
	}
	return int32(off + slot.Off)
}

// fieldtrack adds R_USEFIELD relocations to fnsym to record any
// struct fields that it used.
func fieldtrack(fnsym *obj.LSym, tracked map[*obj.LSym]struct{}) {
	if fnsym == nil {
		return
	}
	if !buildcfg.Experiment.FieldTrack || len(tracked) == 0 {
		return
	}

	trackSyms := make([]*obj.LSym, 0, len(tracked))
	for sym := range tracked {
		trackSyms = append(trackSyms, sym)
	}
	slices.SortFunc(trackSyms, func(a, b *obj.LSym) int { return strings.Compare(a.Name, b.Name) })
	for _, sym := range trackSyms {
		fnsym.AddRel(base.Ctxt, obj.Reloc{Type: objabi.R_USEFIELD, Sym: sym})
	}
}

// largeStack is info about a function whose stack frame is too large (rare).
type largeStack struct {
	locals int64
	args   int64
	callee int64
	pos    src.XPos
}

var (
	largeStackFramesMu sync.Mutex // protects largeStackFrames
	largeStackFrames   []largeStack
)

func CheckLargeStacks() {
	// Check whether any of the functions we have compiled have gigantic stack frames.
	sort.Slice(largeStackFrames, func(i, j int) bool {
		return largeStackFrames[i].pos.Before(largeStackFrames[j].pos)
	})
	for _, large := range largeStackFrames {
		if large.callee != 0 {
			base.ErrorfAt(large.pos, 0, "stack frame too large (>1GB): %d MB locals + %d MB args + %d MB callee", large.locals>>20, large.args>>20, large.callee>>20)
		} else {
			base.ErrorfAt(large.pos, 0, "stack frame too large (>1GB): %d MB locals + %d MB args", large.locals>>20, large.args>>20)
		}
	}
}
```