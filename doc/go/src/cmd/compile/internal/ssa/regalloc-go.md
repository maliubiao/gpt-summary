Response: The user wants a summary of the Go code provided. I need to identify the main functionalities of the code snippet. The code clearly deals with register allocation in the Go compiler. I should break down the key steps involved in this process as described in the comments.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Task:** The initial comments clearly state "Register allocation." This is the central theme.

2. **Key Algorithm:** The comments mention "linear scan register allocator."  This is a crucial piece of information.

3. **Handling Merges:**  The text talks about "merge edges" and the need to "shuffle data." This indicates a mechanism to reconcile register assignments across different control flow paths.

4. **Greedy Approach:**  The code uses a "greedy allocator" that operates based on when values are used and spills when necessary.

5. **Spilling Mechanism:**  The comments detail how values are "spilled" to the stack when registers are needed and how they are "restored" later. This is a core part of register allocation.

6. **Phi Functions:**  The code specifically discusses "phi values," distinguishing between "register" and "stack" phis, indicating how the allocator handles merging values at control flow join points.

7. **Dominance:**  The concept of "dominator" is mentioned in the context of scheduling spills. This suggests the allocator is aware of control flow relationships.

8. **Data Structures:** The code defines several key data structures like `regAllocState`, `valState`, `regState`, `use`, etc. While listing all details isn't necessary for a high-level summary, recognizing their existence is important.

9. **Key Functions:** Functions like `regalloc`, `allocReg`, `makeSpill`, and `placeSpills` seem central to the allocation process.

10. **Error Handling and Debugging:** The presence of `f.Fatalf` and `f.pass.debug` suggests mechanisms for error detection and debugging during the allocation process.

11. **Concurrency (or lack thereof):**  The code seems to operate on a single function at a time, suggesting a sequential allocation process within a function.

12. **Architectural Considerations:**  The code mentions `f.Config` and different register types (GP, FP, special), indicating awareness of the target architecture. WASM is explicitly mentioned as a special case.

13. **Limitations and TODOs:**  The comments contain "TODO" sections, pointing out areas for future improvement, such as affinity graphs and handling non-SSA output. Acknowledging these limitations is important for a complete picture.

14. **Refining the Summary:**  Based on these points, I can formulate a concise summary that captures the essential functionalities of the code. The goal is to provide a high-level overview of what this part of the Go compiler is doing.

By considering these elements, I can arrive at a summary that accurately reflects the functionality of the provided Go code snippet. The instructions to focus on *functions*, *data structures*, *algorithms*, and potential *misunderstandings* guide the content of the summary.
代码的功能是实现 Go 语言编译器的**寄存器分配**过程。 这是线性扫描寄存器分配器的一部分，负责将程序中的虚拟寄存器映射到目标机器的物理寄存器，或者在物理寄存器不足时将值溢出到栈上。

以下是其主要功能点的归纳：

1. **线性扫描分配**: 将整个函数视为一个大的基本块进行贪婪的寄存器分配。
2. **处理合并边**:  对于目标块有多个前驱的合并边，会插入 shuffle 代码，将数据移动到目标块期望的位置。
3. **贪婪分配策略**:  在值即将被使用时将其加载到寄存器，只有在必要时才溢出寄存器，并且溢出未来最晚使用的值。
4. **块调度依赖**: 要求一个块只有在其至少一个前驱被调度后才能被调度，并以前驱的寄存器状态作为起始状态。
5. **无关键边要求**: 要求函数没有关键边，简化了在合并边上添加修复代码的过程。
6. **溢出 (Spilling)**:
    - 当没有空闲寄存器时，将当前存活的值从寄存器中移除并存储到栈上。
    - 当后续需要该值时，从栈上加载回寄存器。
    - 涉及到 `StoreReg` (溢出到栈) 和 `LoadReg` (从栈加载) 指令的插入。
    - 确定 `StoreReg` 指令插入位置的策略，需要保证溢出操作支配所有对该值的恢复操作。
7. **Phi 函数处理**:
    - 区分 "寄存器 phi" 和 "栈 phi"。
    - **寄存器 phi**:  phi 节点和所有输入分配到同一个寄存器，溢出方式与普通操作类似。
    - **栈 phi**:  phi 节点和所有输入分配到同一个栈位置。输入必须是前驱块末尾的 `StoreReg` 指令。
8. **TODO 注释**:  指出了一些未来可能改进的方向，例如使用亲和图来优化寄存器分配，减少不必要的移动。
9. **非严格 SSA 输出**:  提到寄存器分配后输出的代码可能不再严格符合 SSA 形式，并解释了可能出现这种情况的原因。

**虽然这段代码本身不包含完整的 Go 语言功能的实现，但它属于 Go 语言编译器中至关重要的一个环节，负责将高级的、与架构无关的中间表示转换为更接近目标机器代码的形式。**

**基于代码的推断，以下是一个简单的 Go 代码示例，可以展示寄存器分配器需要处理的情况：**

```go
package main

func add(a, b int) int {
	c := a + b
	return c
}

func main() {
	x := 10
	y := 20
	z := add(x, y)
	println(z)
}
```

**假设的输入 (SSA 中间表示，简化版):**

```
# function main
b1:
    v1 = ConstInt 10
    v2 = ConstInt 20
    goto b2

b2:
    v3 = Call add(v1, v2)
    goto b3

b3:
    v4 = Println v3
    Ret
```

**假设的输出 (经过寄存器分配后的中间表示，简化版，假设目标架构有寄存器 AX, BX):**

```
# function main
b1:
    v1 = ConstInt 10 : AX  // v1 加载到 AX 寄存器
    v2 = ConstInt 20 : BX  // v2 加载到 BX 寄存器
    goto b2

b2:
    // 假设 add 函数的参数通过寄存器传递
    // 可能需要 move 指令将 v1 和 v2 的值移动到参数寄存器
    v3 = Call add(AX, BX)  // 调用 add 函数，参数为 AX 和 BX 寄存器
    goto b3

b3:
    // 假设 println 函数的参数通过寄存器传递
    // 可能需要 move 指令将 v3 的值移动到参数寄存器
    v4 = Println v3  // 假设 v3 的结果已经在某个寄存器中
    Ret
```

**代码推理与假设的输入输出:**

- **假设**: 目标架构有通用寄存器 AX 和 BX。
- **输入**:  `v1` 和 `v2` 是常量整数。
- **输出**: 寄存器分配器将 `v1` 分配到 `AX`，`v2` 分配到 `BX`。
- **推理**:  当调用 `add` 函数时，寄存器分配器可能需要将 `v1` 和 `v2` 的值移动到函数调用约定的参数寄存器中（假设 `add` 函数通过寄存器接收参数）。  类似地，调用 `println` 函数时也可能需要移动结果值到参数寄存器。

**这段代码不涉及命令行参数的具体处理。**  命令行参数的处理通常发生在编译器的前端部分，而寄存器分配是编译器的后端优化阶段。

**使用者易犯错的点 (针对编译器开发者):**

这段代码是编译器内部实现的一部分，直接使用者是 Go 语言编译器的开发者。 开发者在修改或扩展寄存器分配器时可能犯错的点包括：

- **不正确的活跃性分析**: 如果活跃性分析不准确，可能会导致在值仍然存活的时候被溢出，或者在值已经死亡的时候仍然占用寄存器。
- **错误的溢出/恢复逻辑**:  溢出和恢复的逻辑必须正确，否则会导致程序运行时读取到错误的值。
- **没有正确处理所有指令的寄存器约束**:  不同的指令对操作数所在的寄存器有不同的约束，例如某些指令只能使用特定的寄存器。如果寄存器分配器没有考虑到这些约束，会导致生成的代码无法执行。
- **没有正确处理调用约定**:  函数调用涉及到参数和返回值的传递，需要遵循特定的调用约定。寄存器分配器需要确保参数和返回值被放置在正确的寄存器或栈位置。
- **过度溢出**:  过于频繁地溢出寄存器会降低程序的性能。
- **不必要的寄存器移动**:  没有充分利用值的生命周期，导致不必要的寄存器间移动。

**总结一下它的功能:**

这段 `regalloc.go` 代码是 Go 语言编译器中实现线性扫描寄存器分配的核心部分。 它负责将中间表示形式的程序变量分配到目标机器的物理寄存器，并在寄存器不足时处理值的溢出和恢复，同时处理控制流合并点处的寄存器状态同步。 它的目标是高效地利用有限的寄存器资源，生成高性能的目标代码。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/regalloc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Register allocation.
//
// We use a version of a linear scan register allocator. We treat the
// whole function as a single long basic block and run through
// it using a greedy register allocator. Then all merge edges
// (those targeting a block with len(Preds)>1) are processed to
// shuffle data into the place that the target of the edge expects.
//
// The greedy allocator moves values into registers just before they
// are used, spills registers only when necessary, and spills the
// value whose next use is farthest in the future.
//
// The register allocator requires that a block is not scheduled until
// at least one of its predecessors have been scheduled. The most recent
// such predecessor provides the starting register state for a block.
//
// It also requires that there are no critical edges (critical =
// comes from a block with >1 successor and goes to a block with >1
// predecessor).  This makes it easy to add fixup code on merge edges -
// the source of a merge edge has only one successor, so we can add
// fixup code to the end of that block.

// Spilling
//
// During the normal course of the allocator, we might throw a still-live
// value out of all registers. When that value is subsequently used, we must
// load it from a slot on the stack. We must also issue an instruction to
// initialize that stack location with a copy of v.
//
// pre-regalloc:
//   (1) v = Op ...
//   (2) x = Op ...
//   (3) ... = Op v ...
//
// post-regalloc:
//   (1) v = Op ...    : AX // computes v, store result in AX
//       s = StoreReg v     // spill v to a stack slot
//   (2) x = Op ...    : AX // some other op uses AX
//       c = LoadReg s : CX // restore v from stack slot
//   (3) ... = Op c ...     // use the restored value
//
// Allocation occurs normally until we reach (3) and we realize we have
// a use of v and it isn't in any register. At that point, we allocate
// a spill (a StoreReg) for v. We can't determine the correct place for
// the spill at this point, so we allocate the spill as blockless initially.
// The restore is then generated to load v back into a register so it can
// be used. Subsequent uses of v will use the restored value c instead.
//
// What remains is the question of where to schedule the spill.
// During allocation, we keep track of the dominator of all restores of v.
// The spill of v must dominate that block. The spill must also be issued at
// a point where v is still in a register.
//
// To find the right place, start at b, the block which dominates all restores.
//  - If b is v.Block, then issue the spill right after v.
//    It is known to be in a register at that point, and dominates any restores.
//  - Otherwise, if v is in a register at the start of b,
//    put the spill of v at the start of b.
//  - Otherwise, set b = immediate dominator of b, and repeat.
//
// Phi values are special, as always. We define two kinds of phis, those
// where the merge happens in a register (a "register" phi) and those where
// the merge happens in a stack location (a "stack" phi).
//
// A register phi must have the phi and all of its inputs allocated to the
// same register. Register phis are spilled similarly to regular ops.
//
// A stack phi must have the phi and all of its inputs allocated to the same
// stack location. Stack phis start out life already spilled - each phi
// input must be a store (using StoreReg) at the end of the corresponding
// predecessor block.
//     b1: y = ... : AX        b2: z = ... : BX
//         y2 = StoreReg y         z2 = StoreReg z
//         goto b3                 goto b3
//     b3: x = phi(y2, z2)
// The stack allocator knows that StoreReg args of stack-allocated phis
// must be allocated to the same stack slot as the phi that uses them.
// x is now a spilled value and a restore must appear before its first use.

// TODO

// Use an affinity graph to mark two values which should use the
// same register. This affinity graph will be used to prefer certain
// registers for allocation. This affinity helps eliminate moves that
// are required for phi implementations and helps generate allocations
// for 2-register architectures.

// Note: regalloc generates a not-quite-SSA output. If we have:
//
//             b1: x = ... : AX
//                 x2 = StoreReg x
//                 ... AX gets reused for something else ...
//                 if ... goto b3 else b4
//
//   b3: x3 = LoadReg x2 : BX       b4: x4 = LoadReg x2 : CX
//       ... use x3 ...                 ... use x4 ...
//
//             b2: ... use x3 ...
//
// If b3 is the primary predecessor of b2, then we use x3 in b2 and
// add a x4:CX->BX copy at the end of b4.
// But the definition of x3 doesn't dominate b2.  We should really
// insert an extra phi at the start of b2 (x5=phi(x3,x4):BX) to keep
// SSA form. For now, we ignore this problem as remaining in strict
// SSA form isn't needed after regalloc. We'll just leave the use
// of x3 not dominated by the definition of x3, and the CX->BX copy
// will have no use (so don't run deadcode after regalloc!).
// TODO: maybe we should introduce these extra phis?

package ssa

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/types"
	"cmd/internal/src"
	"cmd/internal/sys"
	"fmt"
	"internal/buildcfg"
	"math"
	"math/bits"
	"unsafe"
)

const (
	moveSpills = iota
	logSpills
	regDebug
	stackDebug
)

// distance is a measure of how far into the future values are used.
// distance is measured in units of instructions.
const (
	likelyDistance   = 1
	normalDistance   = 10
	unlikelyDistance = 100
)

// regalloc performs register allocation on f. It sets f.RegAlloc
// to the resulting allocation.
func regalloc(f *Func) {
	var s regAllocState
	s.init(f)
	s.regalloc(f)
	s.close()
}

type register uint8

const noRegister register = 255

// For bulk initializing
var noRegisters [32]register = [32]register{
	noRegister, noRegister, noRegister, noRegister, noRegister, noRegister, noRegister, noRegister,
	noRegister, noRegister, noRegister, noRegister, noRegister, noRegister, noRegister, noRegister,
	noRegister, noRegister, noRegister, noRegister, noRegister, noRegister, noRegister, noRegister,
	noRegister, noRegister, noRegister, noRegister, noRegister, noRegister, noRegister, noRegister,
}

// A regMask encodes a set of machine registers.
// TODO: regMask -> regSet?
type regMask uint64

func (m regMask) String() string {
	s := ""
	for r := register(0); m != 0; r++ {
		if m>>r&1 == 0 {
			continue
		}
		m &^= regMask(1) << r
		if s != "" {
			s += " "
		}
		s += fmt.Sprintf("r%d", r)
	}
	return s
}

func (s *regAllocState) RegMaskString(m regMask) string {
	str := ""
	for r := register(0); m != 0; r++ {
		if m>>r&1 == 0 {
			continue
		}
		m &^= regMask(1) << r
		if str != "" {
			str += " "
		}
		str += s.registers[r].String()
	}
	return str
}

// countRegs returns the number of set bits in the register mask.
func countRegs(r regMask) int {
	return bits.OnesCount64(uint64(r))
}

// pickReg picks an arbitrary register from the register mask.
func pickReg(r regMask) register {
	if r == 0 {
		panic("can't pick a register from an empty set")
	}
	// pick the lowest one
	return register(bits.TrailingZeros64(uint64(r)))
}

type use struct {
	// distance from start of the block to a use of a value
	//   dist == 0                 used by first instruction in block
	//   dist == len(b.Values)-1   used by last instruction in block
	//   dist == len(b.Values)     used by block's control value
	//   dist  > len(b.Values)     used by a subsequent block
	dist int32
	pos  src.XPos // source position of the use
	next *use     // linked list of uses of a value in nondecreasing dist order
}

// A valState records the register allocation state for a (pre-regalloc) value.
type valState struct {
	regs              regMask // the set of registers holding a Value (usually just one)
	uses              *use    // list of uses in this block
	spill             *Value  // spilled copy of the Value (if any)
	restoreMin        int32   // minimum of all restores' blocks' sdom.entry
	restoreMax        int32   // maximum of all restores' blocks' sdom.exit
	needReg           bool    // cached value of !v.Type.IsMemory() && !v.Type.IsVoid() && !.v.Type.IsFlags()
	rematerializeable bool    // cached value of v.rematerializeable()
}

type regState struct {
	v *Value // Original (preregalloc) Value stored in this register.
	c *Value // A Value equal to v which is currently in a register.  Might be v or a copy of it.
	// If a register is unused, v==c==nil
}

type regAllocState struct {
	f *Func

	sdom        SparseTree
	registers   []Register
	numRegs     register
	SPReg       register
	SBReg       register
	GReg        register
	allocatable regMask

	// live values at the end of each block.  live[b.ID] is a list of value IDs
	// which are live at the end of b, together with a count of how many instructions
	// forward to the next use.
	live [][]liveInfo
	// desired register assignments at the end of each block.
	// Note that this is a static map computed before allocation occurs. Dynamic
	// register desires (from partially completed allocations) will trump
	// this information.
	desired []desiredState

	// current state of each (preregalloc) Value
	values []valState

	// ID of SP, SB values
	sp, sb ID

	// For each Value, map from its value ID back to the
	// preregalloc Value it was derived from.
	orig []*Value

	// current state of each register
	regs []regState

	// registers that contain values which can't be kicked out
	nospill regMask

	// mask of registers currently in use
	used regMask

	// mask of registers used since the start of the current block
	usedSinceBlockStart regMask

	// mask of registers used in the current instruction
	tmpused regMask

	// current block we're working on
	curBlock *Block

	// cache of use records
	freeUseRecords *use

	// endRegs[blockid] is the register state at the end of each block.
	// encoded as a set of endReg records.
	endRegs [][]endReg

	// startRegs[blockid] is the register state at the start of merge blocks.
	// saved state does not include the state of phi ops in the block.
	startRegs [][]startReg

	// startRegsMask is a mask of the registers in startRegs[curBlock.ID].
	// Registers dropped from startRegsMask are later synchronoized back to
	// startRegs by dropping from there as well.
	startRegsMask regMask

	// spillLive[blockid] is the set of live spills at the end of each block
	spillLive [][]ID

	// a set of copies we generated to move things around, and
	// whether it is used in shuffle. Unused copies will be deleted.
	copies map[*Value]bool

	loopnest *loopnest

	// choose a good order in which to visit blocks for allocation purposes.
	visitOrder []*Block

	// blockOrder[b.ID] corresponds to the index of block b in visitOrder.
	blockOrder []int32

	// whether to insert instructions that clobber dead registers at call sites
	doClobber bool

	// For each instruction index in a basic block, the index of the next call
	// at or after that instruction index.
	// If there is no next call, returns maxInt32.
	// nextCall for a call instruction points to itself.
	// (Indexes and results are pre-regalloc.)
	nextCall []int32

	// Index of the instruction we're currently working on.
	// Index is expressed in terms of the pre-regalloc b.Values list.
	curIdx int
}

type endReg struct {
	r register
	v *Value // pre-regalloc value held in this register (TODO: can we use ID here?)
	c *Value // cached version of the value
}

type startReg struct {
	r   register
	v   *Value   // pre-regalloc value needed in this register
	c   *Value   // cached version of the value
	pos src.XPos // source position of use of this register
}

// freeReg frees up register r. Any current user of r is kicked out.
func (s *regAllocState) freeReg(r register) {
	v := s.regs[r].v
	if v == nil {
		s.f.Fatalf("tried to free an already free register %d\n", r)
	}

	// Mark r as unused.
	if s.f.pass.debug > regDebug {
		fmt.Printf("freeReg %s (dump %s/%s)\n", &s.registers[r], v, s.regs[r].c)
	}
	s.regs[r] = regState{}
	s.values[v.ID].regs &^= regMask(1) << r
	s.used &^= regMask(1) << r
}

// freeRegs frees up all registers listed in m.
func (s *regAllocState) freeRegs(m regMask) {
	for m&s.used != 0 {
		s.freeReg(pickReg(m & s.used))
	}
}

// clobberRegs inserts instructions that clobber registers listed in m.
func (s *regAllocState) clobberRegs(m regMask) {
	m &= s.allocatable & s.f.Config.gpRegMask // only integer register can contain pointers, only clobber them
	for m != 0 {
		r := pickReg(m)
		m &^= 1 << r
		x := s.curBlock.NewValue0(src.NoXPos, OpClobberReg, types.TypeVoid)
		s.f.setHome(x, &s.registers[r])
	}
}

// setOrig records that c's original value is the same as
// v's original value.
func (s *regAllocState) setOrig(c *Value, v *Value) {
	if int(c.ID) >= cap(s.orig) {
		x := s.f.Cache.allocValueSlice(int(c.ID) + 1)
		copy(x, s.orig)
		s.f.Cache.freeValueSlice(s.orig)
		s.orig = x
	}
	for int(c.ID) >= len(s.orig) {
		s.orig = append(s.orig, nil)
	}
	if s.orig[c.ID] != nil {
		s.f.Fatalf("orig value set twice %s %s", c, v)
	}
	s.orig[c.ID] = s.orig[v.ID]
}

// assignReg assigns register r to hold c, a copy of v.
// r must be unused.
func (s *regAllocState) assignReg(r register, v *Value, c *Value) {
	if s.f.pass.debug > regDebug {
		fmt.Printf("assignReg %s %s/%s\n", &s.registers[r], v, c)
	}
	if s.regs[r].v != nil {
		s.f.Fatalf("tried to assign register %d to %s/%s but it is already used by %s", r, v, c, s.regs[r].v)
	}

	// Update state.
	s.regs[r] = regState{v, c}
	s.values[v.ID].regs |= regMask(1) << r
	s.used |= regMask(1) << r
	s.f.setHome(c, &s.registers[r])
}

// allocReg chooses a register from the set of registers in mask.
// If there is no unused register, a Value will be kicked out of
// a register to make room.
func (s *regAllocState) allocReg(mask regMask, v *Value) register {
	if v.OnWasmStack {
		return noRegister
	}

	mask &= s.allocatable
	mask &^= s.nospill
	if mask == 0 {
		s.f.Fatalf("no register available for %s", v.LongString())
	}

	// Pick an unused register if one is available.
	if mask&^s.used != 0 {
		r := pickReg(mask &^ s.used)
		s.usedSinceBlockStart |= regMask(1) << r
		return r
	}

	// Pick a value to spill. Spill the value with the
	// farthest-in-the-future use.
	// TODO: Prefer registers with already spilled Values?
	// TODO: Modify preference using affinity graph.
	// TODO: if a single value is in multiple registers, spill one of them
	// before spilling a value in just a single register.

	// Find a register to spill. We spill the register containing the value
	// whose next use is as far in the future as possible.
	// https://en.wikipedia.org/wiki/Page_replacement_algorithm#The_theoretically_optimal_page_replacement_algorithm
	var r register
	maxuse := int32(-1)
	for t := register(0); t < s.numRegs; t++ {
		if mask>>t&1 == 0 {
			continue
		}
		v := s.regs[t].v
		if n := s.values[v.ID].uses.dist; n > maxuse {
			// v's next use is farther in the future than any value
			// we've seen so far. A new best spill candidate.
			r = t
			maxuse = n
		}
	}
	if maxuse == -1 {
		s.f.Fatalf("couldn't find register to spill")
	}

	if s.f.Config.ctxt.Arch.Arch == sys.ArchWasm {
		// TODO(neelance): In theory this should never happen, because all wasm registers are equal.
		// So if there is still a free register, the allocation should have picked that one in the first place instead of
		// trying to kick some other value out. In practice, this case does happen and it breaks the stack optimization.
		s.freeReg(r)
		return r
	}

	// Try to move it around before kicking out, if there is a free register.
	// We generate a Copy and record it. It will be deleted if never used.
	v2 := s.regs[r].v
	m := s.compatRegs(v2.Type) &^ s.used &^ s.tmpused &^ (regMask(1) << r)
	if m != 0 && !s.values[v2.ID].rematerializeable && countRegs(s.values[v2.ID].regs) == 1 {
		s.usedSinceBlockStart |= regMask(1) << r
		r2 := pickReg(m)
		c := s.curBlock.NewValue1(v2.Pos, OpCopy, v2.Type, s.regs[r].c)
		s.copies[c] = false
		if s.f.pass.debug > regDebug {
			fmt.Printf("copy %s to %s : %s\n", v2, c, &s.registers[r2])
		}
		s.setOrig(c, v2)
		s.assignReg(r2, v2, c)
	}

	// If the evicted register isn't used between the start of the block
	// and now then there is no reason to even request it on entry. We can
	// drop from startRegs in that case.
	if s.usedSinceBlockStart&(regMask(1)<<r) == 0 {
		if s.startRegsMask&(regMask(1)<<r) == 1 {
			if s.f.pass.debug > regDebug {
				fmt.Printf("dropped from startRegs: %s\n", &s.registers[r])
			}
			s.startRegsMask &^= regMask(1) << r
		}
	}

	s.freeReg(r)
	s.usedSinceBlockStart |= regMask(1) << r
	return r
}

// makeSpill returns a Value which represents the spilled value of v.
// b is the block in which the spill is used.
func (s *regAllocState) makeSpill(v *Value, b *Block) *Value {
	vi := &s.values[v.ID]
	if vi.spill != nil {
		// Final block not known - keep track of subtree where restores reside.
		vi.restoreMin = min(vi.restoreMin, s.sdom[b.ID].entry)
		vi.restoreMax = max(vi.restoreMax, s.sdom[b.ID].exit)
		return vi.spill
	}
	// Make a spill for v. We don't know where we want
	// to put it yet, so we leave it blockless for now.
	spill := s.f.newValueNoBlock(OpStoreReg, v.Type, v.Pos)
	// We also don't know what the spill's arg will be.
	// Leave it argless for now.
	s.setOrig(spill, v)
	vi.spill = spill
	vi.restoreMin = s.sdom[b.ID].entry
	vi.restoreMax = s.sdom[b.ID].exit
	return spill
}

// allocValToReg allocates v to a register selected from regMask and
// returns the register copy of v. Any previous user is kicked out and spilled
// (if necessary). Load code is added at the current pc. If nospill is set the
// allocated register is marked nospill so the assignment cannot be
// undone until the caller allows it by clearing nospill. Returns a
// *Value which is either v or a copy of v allocated to the chosen register.
func (s *regAllocState) allocValToReg(v *Value, mask regMask, nospill bool, pos src.XPos) *Value {
	if s.f.Config.ctxt.Arch.Arch == sys.ArchWasm && v.rematerializeable() {
		c := v.copyIntoWithXPos(s.curBlock, pos)
		c.OnWasmStack = true
		s.setOrig(c, v)
		return c
	}
	if v.OnWasmStack {
		return v
	}

	vi := &s.values[v.ID]
	pos = pos.WithNotStmt()
	// Check if v is already in a requested register.
	if mask&vi.regs != 0 {
		r := pickReg(mask & vi.regs)
		if s.regs[r].v != v || s.regs[r].c == nil {
			panic("bad register state")
		}
		if nospill {
			s.nospill |= regMask(1) << r
		}
		s.usedSinceBlockStart |= regMask(1) << r
		return s.regs[r].c
	}

	var r register
	// If nospill is set, the value is used immediately, so it can live on the WebAssembly stack.
	onWasmStack := nospill && s.f.Config.ctxt.Arch.Arch == sys.ArchWasm
	if !onWasmStack {
		// Allocate a register.
		r = s.allocReg(mask, v)
	}

	// Allocate v to the new register.
	var c *Value
	if vi.regs != 0 {
		// Copy from a register that v is already in.
		r2 := pickReg(vi.regs)
		if s.regs[r2].v != v {
			panic("bad register state")
		}
		s.usedSinceBlockStart |= regMask(1) << r2
		c = s.curBlock.NewValue1(pos, OpCopy, v.Type, s.regs[r2].c)
	} else if v.rematerializeable() {
		// Rematerialize instead of loading from the spill location.
		c = v.copyIntoWithXPos(s.curBlock, pos)
	} else {
		// Load v from its spill location.
		spill := s.makeSpill(v, s.curBlock)
		if s.f.pass.debug > logSpills {
			s.f.Warnl(vi.spill.Pos, "load spill for %v from %v", v, spill)
		}
		c = s.curBlock.NewValue1(pos, OpLoadReg, v.Type, spill)
	}

	s.setOrig(c, v)

	if onWasmStack {
		c.OnWasmStack = true
		return c
	}

	s.assignReg(r, v, c)
	if c.Op == OpLoadReg && s.isGReg(r) {
		s.f.Fatalf("allocValToReg.OpLoadReg targeting g: " + c.LongString())
	}
	if nospill {
		s.nospill |= regMask(1) << r
	}
	return c
}

// isLeaf reports whether f performs any calls.
func isLeaf(f *Func) bool {
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op.IsCall() && !v.Op.IsTailCall() {
				// tail call is not counted as it does not save the return PC or need a frame
				return false
			}
		}
	}
	return true
}

// needRegister reports whether v needs a register.
func (v *Value) needRegister() bool {
	return !v.Type.IsMemory() && !v.Type.IsVoid() && !v.Type.IsFlags() && !v.Type.IsTuple()
}

func (s *regAllocState) init(f *Func) {
	s.f = f
	s.f.RegAlloc = s.f.Cache.locs[:0]
	s.registers = f.Config.registers
	if nr := len(s.registers); nr == 0 || nr > int(noRegister) || nr > int(unsafe.Sizeof(regMask(0))*8) {
		s.f.Fatalf("bad number of registers: %d", nr)
	} else {
		s.numRegs = register(nr)
	}
	// Locate SP, SB, and g registers.
	s.SPReg = noRegister
	s.SBReg = noRegister
	s.GReg = noRegister
	for r := register(0); r < s.numRegs; r++ {
		switch s.registers[r].String() {
		case "SP":
			s.SPReg = r
		case "SB":
			s.SBReg = r
		case "g":
			s.GReg = r
		}
	}
	// Make sure we found all required registers.
	switch noRegister {
	case s.SPReg:
		s.f.Fatalf("no SP register found")
	case s.SBReg:
		s.f.Fatalf("no SB register found")
	case s.GReg:
		if f.Config.hasGReg {
			s.f.Fatalf("no g register found")
		}
	}

	// Figure out which registers we're allowed to use.
	s.allocatable = s.f.Config.gpRegMask | s.f.Config.fpRegMask | s.f.Config.specialRegMask
	s.allocatable &^= 1 << s.SPReg
	s.allocatable &^= 1 << s.SBReg
	if s.f.Config.hasGReg {
		s.allocatable &^= 1 << s.GReg
	}
	if buildcfg.FramePointerEnabled && s.f.Config.FPReg >= 0 {
		s.allocatable &^= 1 << uint(s.f.Config.FPReg)
	}
	if s.f.Config.LinkReg != -1 {
		if isLeaf(f) {
			// Leaf functions don't save/restore the link register.
			s.allocatable &^= 1 << uint(s.f.Config.LinkReg)
		}
	}
	if s.f.Config.ctxt.Flag_dynlink {
		switch s.f.Config.arch {
		case "386":
			// nothing to do.
			// Note that for Flag_shared (position independent code)
			// we do need to be careful, but that carefulness is hidden
			// in the rewrite rules so we always have a free register
			// available for global load/stores. See _gen/386.rules (search for Flag_shared).
		case "amd64":
			s.allocatable &^= 1 << 15 // R15
		case "arm":
			s.allocatable &^= 1 << 9 // R9
		case "arm64":
			// nothing to do
		case "loong64": // R2 (aka TP) already reserved.
			// nothing to do
		case "ppc64le": // R2 already reserved.
			// nothing to do
		case "riscv64": // X3 (aka GP) and X4 (aka TP) already reserved.
			// nothing to do
		case "s390x":
			s.allocatable &^= 1 << 11 // R11
		default:
			s.f.fe.Fatalf(src.NoXPos, "arch %s not implemented", s.f.Config.arch)
		}
	}

	// Linear scan register allocation can be influenced by the order in which blocks appear.
	// Decouple the register allocation order from the generated block order.
	// This also creates an opportunity for experiments to find a better order.
	s.visitOrder = layoutRegallocOrder(f)

	// Compute block order. This array allows us to distinguish forward edges
	// from backward edges and compute how far they go.
	s.blockOrder = make([]int32, f.NumBlocks())
	for i, b := range s.visitOrder {
		s.blockOrder[b.ID] = int32(i)
	}

	s.regs = make([]regState, s.numRegs)
	nv := f.NumValues()
	if cap(s.f.Cache.regallocValues) >= nv {
		s.f.Cache.regallocValues = s.f.Cache.regallocValues[:nv]
	} else {
		s.f.Cache.regallocValues = make([]valState, nv)
	}
	s.values = s.f.Cache.regallocValues
	s.orig = s.f.Cache.allocValueSlice(nv)
	s.copies = make(map[*Value]bool)
	for _, b := range s.visitOrder {
		for _, v := range b.Values {
			if v.needRegister() {
				s.values[v.ID].needReg = true
				s.values[v.ID].rematerializeable = v.rematerializeable()
				s.orig[v.ID] = v
			}
			// Note: needReg is false for values returning Tuple types.
			// Instead, we mark the corresponding Selects as needReg.
		}
	}
	s.computeLive()

	s.endRegs = make([][]endReg, f.NumBlocks())
	s.startRegs = make([][]startReg, f.NumBlocks())
	s.spillLive = make([][]ID, f.NumBlocks())
	s.sdom = f.Sdom()

	// wasm: Mark instructions that can be optimized to have their values only on the WebAssembly stack.
	if f.Config.ctxt.Arch.Arch == sys.ArchWasm {
		canLiveOnStack := f.newSparseSet(f.NumValues())
		defer f.retSparseSet(canLiveOnStack)
		for _, b := range f.Blocks {
			// New block. Clear candidate set.
			canLiveOnStack.clear()
			for _, c := range b.ControlValues() {
				if c.Uses == 1 && !opcodeTable[c.Op].generic {
					canLiveOnStack.add(c.ID)
				}
			}
			// Walking backwards.
			for i := len(b.Values) - 1; i >= 0; i-- {
				v := b.Values[i]
				if canLiveOnStack.contains(v.ID) {
					v.OnWasmStack = true
				} else {
					// Value can not live on stack. Values are not allowed to be reordered, so clear candidate set.
					canLiveOnStack.clear()
				}
				for _, arg := range v.Args {
					// Value can live on the stack if:
					// - it is only used once
					// - it is used in the same basic block
					// - it is not a "mem" value
					// - it is a WebAssembly op
					if arg.Uses == 1 && arg.Block == v.Block && !arg.Type.IsMemory() && !opcodeTable[arg.Op].generic {
						canLiveOnStack.add(arg.ID)
					}
				}
			}
		}
	}

	// The clobberdeadreg experiment inserts code to clobber dead registers
	// at call sites.
	// Ignore huge functions to avoid doing too much work.
	if base.Flag.ClobberDeadReg && len(s.f.Blocks) <= 10000 {
		// TODO: honor GOCLOBBERDEADHASH, or maybe GOSSAHASH.
		s.doClobber = true
	}
}

func (s *regAllocState) close() {
	s.f.Cache.freeValueSlice(s.orig)
}

// Adds a use record for id at distance dist from the start of the block.
// All calls to addUse must happen with nonincreasing dist.
func (s *regAllocState) addUse(id ID, dist int32, pos src.XPos) {
	r := s.freeUseRecords
	if r != nil {
		s.freeUseRecords = r.next
	} else {
		r = &use{}
	}
	r.dist = dist
	r.pos = pos
	r.next = s.values[id].uses
	s.values[id].uses = r
	if r.next != nil && dist > r.next.dist {
		s.f.Fatalf("uses added in wrong order")
	}
}

// advanceUses advances the uses of v's args from the state before v to the state after v.
// Any values which have no more uses are deallocated from registers.
func (s *regAllocState) advanceUses(v *Value) {
	for _, a := range v.Args {
		if !s.values[a.ID].needReg {
			continue
		}
		ai := &s.values[a.ID]
		r := ai.uses
		ai.uses = r.next
		if r.next == nil || (a.Op != OpSP && a.Op != OpSB && r.next.dist > s.nextCall[s.curIdx]) {
			// Value is dead (or is not used again until after a call), free all registers that hold it.
			s.freeRegs(ai.regs)
		}
		r.next = s.freeUseRecords
		s.freeUseRecords = r
	}
	s.dropIfUnused(v)
}

// Drop v from registers if it isn't used again, or its only uses are after
// a call instruction.
func (s *regAllocState) dropIfUnused(v *Value) {
	if !s.values[v.ID].needReg {
		return
	}
	vi := &s.values[v.ID]
	r := vi.uses
	if r == nil || (v.Op != OpSP && v.Op != OpSB && r.dist > s.nextCall[s.curIdx]) {
		s.freeRegs(vi.regs)
	}
}

// liveAfterCurrentInstruction reports whether v is live after
// the current instruction is completed.  v must be used by the
// current instruction.
func (s *regAllocState) liveAfterCurrentInstruction(v *Value) bool {
	u := s.values[v.ID].uses
	if u == nil {
		panic(fmt.Errorf("u is nil, v = %s, s.values[v.ID] = %v", v.LongString(), s.values[v.ID]))
	}
	d := u.dist
	for u != nil && u.dist == d {
		u = u.next
	}
	return u != nil && u.dist > d
}

// Sets the state of the registers to that encoded in regs.
func (s *regAllocState) setState(regs []endReg) {
	s.freeRegs(s.used)
	for _, x := range regs {
		s.assignReg(x.r, x.v, x.c)
	}
}

// compatRegs returns the set of registers which can store a type t.
func (s *regAllocState) compatRegs(t *types.Type) regMask {
	var m regMask
	if t.IsTuple() || t.IsFlags() {
		return 0
	}
	if t.IsFloat() || t == types.TypeInt128 {
		if t.Kind() == types.TFLOAT32 && s.f.Config.fp32RegMask != 0 {
			m = s.f.Config.fp32RegMask
		} else if t.Kind() == types.TFLOAT64 && s.f.Config.fp64RegMask != 0 {
			m = s.f.Config.fp64RegMask
		} else {
			m = s.f.Config.fpRegMask
		}
	} else {
		m = s.f.Config.gpRegMask
	}
	return m & s.allocatable
}

// regspec returns the regInfo for operation op.
func (s *regAllocState) regspec(v *Value) regInfo {
	op := v.Op
	if op == OpConvert {
		// OpConvert is a generic op, so it doesn't have a
		// register set in the static table. It can use any
		// allocatable integer register.
		m := s.allocatable & s.f.Config.gpRegMask
		return regInfo{inputs: []inputInfo{{regs: m}}, outputs: []outputInfo{{regs: m}}}
	}
	if op == OpArgIntReg {
		reg := v.Block.Func.Config.intParamRegs[v.AuxInt8()]
		return regInfo{outputs: []outputInfo{{regs: 1 << uint(reg)}}}
	}
	if op == OpArgFloatReg {
		reg := v.Block.Func.Config.floatParamRegs[v.AuxInt8()]
		return regInfo{outputs: []outputInfo{{regs: 1 << uint(reg)}}}
	}
	if op.IsCall() {
		if ac, ok := v.Aux.(*AuxCall); ok && ac.reg != nil {
			return *ac.Reg(&opcodeTable[op].reg, s.f.Config)
		}
	}
	if op == OpMakeResult && s.f.OwnAux.reg != nil {
		return *s.f.OwnAux.ResultReg(s.f.Config)
	}
	return opcodeTable[op].reg
}

func (s *regAllocState) isGReg(r register) bool {
	return s.f.Config.hasGReg && s.GReg == r
}

// Dummy value used to represent the value being held in a temporary register.
var tmpVal Value

func (s *regAllocState) regalloc(f *Func) {
	regValLiveSet := f.newSparseSet(f.NumValues()) // set of values that may be live in register
	defer f.retSparseSet(regValLiveSet)
	var oldSched []*Value
	var phis []*Value
	var phiRegs []register
	var args []*Value

	// Data structure used for computing desired registers.
	var desired desiredState

	// Desired registers for inputs & outputs for each instruction in the block.
	type dentry struct {
		out [4]register    // desired output registers
		in  [3][4]register // desired input registers (for inputs 0,1, and 2)
	}
	var dinfo []dentry

	if f.Entry != f.Blocks[0] {
		f.Fatalf("entry block must be first")
	}

	for _, b := range s.visitOrder {
		if s.f.pass.debug > regDebug {
			fmt.Printf("Begin processing block %v\n", b)
		}
		s.curBlock = b
		s.startRegsMask = 0
		s.usedSinceBlockStart = 0

		// Initialize regValLiveSet and uses fields for this block.
		// Walk backwards through the block doing liveness analysis.
		regValLiveSet.clear()
		for _, e := range s.live[b.ID] {
			s.addUse(e.ID, int32(len(b.Values))+e.dist, e.pos) // pseudo-uses from beyond end of block
			regValLiveSet.add(e.ID)
		}
		for _, v := range b.ControlValues() {
			if s.values[v.ID].needReg {
				s.addUse(v.ID, int32(len(b.Values)), b.Pos) // pseudo-use by control values
				regValLiveSet.add(v.ID)
			}
		}
		if len(s.nextCall) < len(b.Values) {
			s.nextCall = append(s.nextCall, make([]int32, len(b.Values)-len(s.nextCall))...)
		}
		var nextCall int32 = math.MaxInt32
		for i := len(b.Values) - 1; i >= 0; i-- {
			v := b.Values[i]
			regValLiveSet.remove(v.ID)
			if v.Op == OpPhi {
				// Remove v from the live set, but don't add
				// any inputs. This is the state the len(b.Preds)>1
				// case below desires; it wants to process phis specially.
				s.nextCall[i] = nextCall
				continue
			}
			if opcodeTable[v.Op].call {
				// Function call clobbers all the registers but SP and SB.
				regValLiveSet.clear()
				if s.sp != 0 && s.values[s.sp].uses != nil {
					regValLiveSet.add(s.sp)
				}
				if s.sb != 0 && s.values[s.sb].uses != nil {
					regValLiveSet.add(s.sb)
				}
				nextCall = int32(i)
			}
			for _, a := range v.Args {
				if !s.values[a.ID].needReg {
					continue
				}
				s.addUse(a.ID, int32(i), v.Pos)
				regValLiveSet.add(a.ID)
			}
			s.nextCall[i] = nextCall
		}
		if s.f.pass.debug > regDebug {
			fmt.Printf("use distances for %s\n", b)
			for i := range s.values {
				vi := &s.values[i]
				u := vi.uses
				if u == nil {
					continue
				}
				fmt.Printf("  v%d:", i)
				for u != nil {
					fmt.Printf(" %d", u.dist)
					u = u.next
				}
				fmt.Println()
			}
		}

		// Make a copy of the block schedule so we can generate a new one in place.
		// We make a separate copy for phis and regular values.
		nphi := 0
		for _, v := range b.Values {
			if v.Op != OpPhi {
				break
			}
			nphi++
		}
		phis = append(phis[:0], b.Values[:nphi]...)
		oldSched = append(oldSched[:0], b.Values[nphi:]...)
		b.Values = b.Values[:0]

		// Initialize start state of block.
		if b == f.Entry {
			// Regalloc state is empty to start.
			if nphi > 0 {
				f.Fatalf("phis in entry block")
			}
		} else if len(b.Preds) == 1 {
			// Start regalloc state with the end state of the previous block.
			s.setState(s.endRegs[b.Preds[0].b.ID])
			if nphi > 0 {
				f.Fatalf("phis in single-predecessor block")
			}
			// Drop any values which are no longer live.
			// This may happen because at the end of p, a value may be
			// live but only used by some other successor of p.
			for r := register(0); r < s.numRegs; r++ {
				v := s.regs[r].v
				if v != nil && !regValLiveSet.contains(v.ID) {
					s.freeReg(r)
				}
			}
		} else {
			// This is the complicated case. We have more than one predecessor,
			// which means we may have Phi ops.

			// Start with the final register state of the predecessor with least spill values.
			// This is based on the following points:
			// 1, The less spill value indicates that the register pressure of this path is smaller,
			//    so the values of this block are more likely to be allocated to registers.
			// 2, Avoid the predecessor that contains the function call, because the predecessor that
			//    contains the function call usually generates a lot of spills and lose the previous
			//    allocation state.
			// TODO: Improve this part. At least the size of endRegs of the predecessor also has
			// an impact on the code size and compiler speed. But it is not easy to find a simple
			// and efficient method that combines multiple factors.
			idx := -1
			for i, p := range b.Preds {
				// If the predecessor has not been visited yet, skip it because its end state
				// (redRegs and spillLive) has not been computed yet.
				pb := p.b
				if s.blockOrder[pb.ID] >= s.blockOrder[b.ID] {
					continue
				}
				if idx == -1 {
					idx = i
					continue
				}
				pSel := b.Preds[idx].b
				if len(s.spillLive[pb.ID]) < len(s.spillLive[pSel.ID]) {
					idx = i
				} else if len(s.spillLive[pb.ID]) == len(s.spillLive[pSel.ID]) {
					// Use a bit of likely information. After critical pass, pb and pSel must
					// be plain blocks, so check edge pb->pb.Preds instead of edge pb->b.
					// TODO: improve the prediction of the likely predecessor. The following
					// method is only suitable for the simplest cases. For complex cases,
					// the prediction may be inaccurate, but this does not affect the
					// correctness of the program.
					// According to the layout algorithm, the predecessor with the
					// smaller blockOrder is the true branch, and the test results show
					// that it is better to choose the predecessor with a smaller
					// blockOrder than no choice.
					if pb.likelyBranch() && !pSel.likelyBranch() || s.blockOrder[pb.ID] < s.blockOrder[pSel.ID] {
						idx = i
					}
				}
			}
			if idx < 0 {
				f.Fatalf("bad visitOrder, no predecessor of %s has been visited before it", b)
			}
			p := b.Preds[idx].b
			s.setState(s.endRegs[p.ID])

			if s.f.pass.debug > regDebug {
				fmt.Printf("starting merge block %s with end state of %s:\n", b, p)
				for _, x := range s.endRegs[p.ID] {
					fmt.Printf("  %s: orig:%s cache:%s\n", &s.registers[x.r], x.v, x.c)
				}
			}

			// Decide on registers for phi ops. Use the registers determined
			// by the primary predecessor if we can.
			// TODO: pick best of (already processed) predecessors?
			// Majority vote? Deepest nesting level?
			phiRegs = phiRegs[:0]
			var phiUsed regMask

			for _, v := range phis {
				if !s.values[v.ID].needReg {
					phiRegs = append(phiRegs, noRegister)
					continue
				}
				a := v.Args[idx]
				// Some instructions target not-allocatable registers.
				// They're not suitable for further (phi-function) allocation.
				m := s.values[a.ID].regs &^ phiUsed & s.allocatable
				if m != 0 {
					r := pickReg(m)
					phiUsed |= regMask(1) << r
					phiRegs = append(phiRegs, r)
				} else {
					phiRegs = append(phiRegs, noRegister)
				}
			}

			// Second pass - deallocate all in-register phi inputs.
			for i, v := range phis {
				if !s.values[v.ID].needReg {
					continue
				}
				a := v.Args[idx]
				r := phiRegs[i]
				if r == noRegister {
					continue
				}
				if regValLiveSet.contains(a.ID) {
					// Input value is still live (it is used by something other than Phi).
					// Try to move it around before kicking out, if there is a free register.
					// We generate a Copy in the predecessor block and record it. It will be
					// deleted later if never used.
					//
					// Pick a free register. At this point some registers used in the predecessor
					// block may have been deallocated. Those are the ones used for Phis. Exclude
					// them (and they are not going to be helpful anyway).
					m := s.compatRegs(a.Type) &^ s.used &^ phiUsed
					if m != 0 && !s.values[a.ID].rematerializeable && countRegs(s.values[a.ID].regs) == 1 {
						r2 := pickReg(m)
						c := p.NewValue1(a.Pos, OpCopy, a.Type, s.regs[r].c)
						s.copies[c] = false
						if s.f.pass.debug > regDebug {
							fmt.Printf("copy %s to %s : %s\n", a, c, &s.registers[r2])
						}
						s.setOrig(c, a)
						s.assignReg(r2, a, c)
						s.endRegs[p.ID] = append(s.endRegs[p.ID], endReg{r2, a, c})
					}
				}
				s.freeReg(r)
			}

			// Copy phi ops into new schedule.
			b.Values = append(b.Values, phis...)

			// Third pass - pick registers for phis whose input
			// was not in a register in the primary predecessor.
			for i, v := range phis {
				if !s.values[v.ID].needReg {
					continue
				}
				if phiRegs[i] != noRegister {
					continue
				}
				m := s.compatRegs(v.Type) &^ phiUsed &^ s.used
				// If one of the other inputs of v is in a register, and the register is available,
				// select this register, which can save some unnecessary copies.
				for i, pe := range b.Preds {
					if i == idx {
						continue
					}
					ri := noRegister
					for _, er := range s.endRegs[pe.b.ID] {
						if er.v == s.orig[v.Args[i].ID] {
							ri = er.r
							break
						}
					}
					if ri != noRegister && m>>ri&1 != 0 {
						m = regMask(1) << ri
						break
					}
				}
				if m != 0 {
					r := pickReg(m)
					phiRegs[i] = r
					phiUsed |= regMask(1) << r
				}
			}

			// Set registers for phis. Add phi spill code.
			for i, v := range phis {
				if !s.values[v.ID].needReg {
					continue
				}
				r := phiRegs[i]
				if r == noRegister {
					// stack-based phi
					// Spills will be inserted in all the predecessors below.
					s.values[v.ID].spill = v // v starts life spilled
					continue
				}
				// register-based phi
				s.assignReg(r, v, v)
			}

			// Deallocate any values which are no longer live. Phis are excluded.
			for r := register(0); r < s.numRegs; r++ {
				if phiUsed>>r&1 != 0 {
					continue
				}
				v := s.regs[r].v
				if v != nil && !regValLiveSet.contains(v.ID) {
					s.freeReg(r)
				}
			}

			// Save the starting state for use by merge edges.
			// We append to a stack allocated variable that we'll
			// later copy into s.startRegs in one fell swoop, to save
			// on allocations.
			regList := make([]startReg, 0, 32)
			for r := register(0); r < s.numRegs; r++ {
				v := s.regs[r].v
				if v == nil {
					continue
				}
				if phiUsed>>r&1 != 0 {
					// Skip registers that phis used, we'll handle those
					// specially during merge edge processing.
					continue
				}
				regList = append(regList, startReg{r, v, s.regs[r].c, s.values[v.ID].uses.pos})
				s.startRegsMask |= regMask(1) << r
			}
			s.startRegs[b.ID] = make([]startReg, len(regList))
			copy(s.startRegs[b.ID], regList)

			if s.f.pass.debug > regDebug {
				fmt.Printf("after phis\n")
				for _, x := range s.startRegs[b.ID] {
					fmt.Printf("  %s: v%d\n", &s.registers[x.r], x.v.ID)
				}
			}
		}

		// Drop phis from registers if they immediately go dead.
		for i, v := range phis {
			s.curIdx = i
			s.dropIfUnused(v)
		}

		// Allocate space to record the desired registers for each value.
		if l := len(oldSched); cap(dinfo) < l {
			dinfo = make([]dentry, l)
		} else {
			dinfo = dinfo[:l]
			for i := range dinfo {
				dinfo[i] = dentry{}
			}
		}

		// Load static desired register info at the end of the block.
		desired.copy(&s.desired[b.ID])

		// Check actual assigned registers at the start of the next block(s).
		// Dynamically assigned registers will trump the static
		// desired registers computed during liveness analysis.
		// Note that we do this phase after startRegs is set above, so that
		// we get the right behavior for a block which branches to itself.
		for _, e := range b.Succs {
			succ := e.b
			// TODO: prioritize likely successor?
			for _, x := range s.startRegs[succ.ID] {
				desired.add(x.v.ID, x.r)
			}
			// Process phi ops in succ.
			pidx := e.i
			for _, v := range succ.Values {
				if v.Op != OpPhi {
					break
				}
				if !s.values[v.ID].needReg {
					continue
				}
				rp, ok := s.f.getHome(v.ID).(*Register)
				if !ok {
					// If v is not assigned a register, pick a register assigned to one of v's inputs.
					// Hopefully v will get assigned that register later.
					// If the inputs have allocated register information, add it to desired,
					// which may reduce spill or copy operations when the register is available.
					for _, a := range v.Args {
						rp, ok = s.f.getHome(a.ID).(*Register)
						if ok {
							break
						}
					}
					if !ok {
						continue
					}
				}
				desired.add(v.Args[pidx].ID, register(rp.num))
			}
		}
		// Walk values backwards computing desired register info.
		// See computeLive for more comments.
		for i := len(oldSched) - 1; i >= 0; i-- {
			v := oldSched[i]
			prefs := desired.remove(v.ID)
			regspec := s.regspec(v)
			desired.clobber(regspec.clobbers)
			for _, j := range regspec.inputs {
				if countRegs(j.regs) != 1 {
					continue
				}
				desired.clobber(j.regs)
				desired.add(v.Args[j.idx].ID, pickReg(j.regs))
			}
			if opcodeTable[v.Op].resultInArg0 || v.Op == OpAMD64ADDQconst || v.Op == OpAMD64ADDLconst || v.Op == OpSelect0 {
				if opcodeTable[v.Op].commutative {
					desired.addList(v.Args[1].ID, prefs)
				}
				desired.addList(v.Args[0].ID, prefs)
			}
			// Save desired registers for this value.
			dinfo[i].out = prefs
			for j, a := range v.Args {
				if j >= len(dinfo[i].in) {
					break
				}
				dinfo[i].in[j] = desired.get(a.ID)
			}
		}

		// Process all the non-phi values.
		for idx, v := range oldSched {
			s.curIdx = nphi + idx
			tmpReg := noRegister
			if s.f.pass.debug > regDebug {
				fmt.Printf("  processing %s\n", v.LongString())
			}
			regspec := s.regspec(v)
			if v.Op == OpPhi {
				f.Fatalf("phi %s not at start of block", v)
			}
			if v.Op == OpSP {
				s.assignReg(s.SPReg, v, v)
				b.Values = append(b.Values, v)
				s.advanceUses(v)
				s.sp = v.ID
				continue
			}
			if v.Op == OpSB {
				s.assignReg(s.SBReg, v, v)
				b.Values = append(b.Values, v)
				s.advanceUses(v)
				s.sb = v.ID
				continue
			}
			if v.Op == OpSelect0 || v.Op == OpSelect1 || v.Op == OpSelectN {
				if s.values[v.ID].needReg {
					if v.Op == OpSelectN {
						s.assignReg(register(s.f.getHome(v.Args[0].ID).(LocResults)[int(v.AuxInt)].(*Register).num), v, v)
					} else {
						var i = 0
						if v.Op == OpSelect1 {
							i = 1
						}
						s.assignReg(register(s.f.getHome(v.Args[0].ID).(LocPair)[i].(*Register).num), v, v)
					}
				}
				b.Values = append(b.Values, v)
				s.advanceUses(v)
				continue
			}
			if v.Op == OpGetG && s.f.Config.hasGReg {
				// use hardware g register
				if s.regs[s.GReg].v != nil {
					s.freeReg(s.GReg) // kick out the old value
				}
				s.assignReg(s.GReg, v, v)
				b.Values = append(b.Values, v)
				s.advanceUses(v)
				continue
			}
			if v.Op == OpArg {
				// Args are "pre-spilled" values. We don't allocate
				// any register here. We just set up the spill pointer to
				// point at itself and any later user will restore it to use it.
				s.values[v.ID].spill = v
				b.Values = append(b.Values, v)
				s.advanceUses(v)
				continue
			}
			if v.Op == OpKeepAlive {
				// Make sure the argument to v is still live here.
				s.advanceUses(v)
				a := v.Args[0]
				vi := &s.values[a.ID]
				if vi.regs == 0 && !vi.rematerializeable {
					// Use the spill location.
					// This forces later liveness analysis to make the
					// value live at this point.
					v.SetArg(0, s.makeSpill(a, b))
				} else if _, ok := a.Aux.(*ir.Name); ok && vi.rematerializeable {
					// Rematerializeable value with a gc.Node. This is the address of
					// a stack object (e.g. an LEAQ). Keep the object live.
					// Change it to VarLive, which is what plive expects for locals.
					v.Op = OpVarLive
					v.SetArgs1(v.Args[1])
					v.Aux = a.Aux
				} else {
					// In-register and rematerializeable values are already live.
					// These are typically rematerializeable constants like nil,
					// or values of a variable that were modified since the last call.
					v.Op = OpCopy
					v.SetArgs1(v.Args[1])
				}
				b.Values = append(b.Values, v)
				continue
			}
			if len(regspec.inputs) == 0 && len(regspec.outputs) == 0 {
				// No register allocation required (or none specified yet)
				if s.doClobber && v.Op.IsCall() {
					s.clobberRegs(regspec.clobbers)
				}
				s.freeRegs(regspec.clobbers)
				b.Values = append(b.Values, v)
				s.advanceUses(v)
				continue
			}

			if s.values[v.ID].rematerializeable {
				// Value is rematerializeable, don't issue it here.
				// It will get issued just before each use (see
				// allocValueToReg).
				for _, a := range v.Args {
					a.Uses--
				}
				s.advanceUses(v)
				continue
			}

			if s.f.pass.debug > regDebug {
				fmt.Printf("value %s\n", v.LongString())
				fmt.Printf("  out:")
				for _, r := range dinfo[idx].out {
					if r != noRegister {
						fmt.Printf(" %s", &s.registers[r])
					}
				}
				fmt.Println()
				for i := 0; i < len(v.Args) && i < 3; i++ {
					fmt.Printf("  in%d:", i)
					for _, r := range dinfo[idx].in[i] {
						if r != noRegister {
							fmt.Printf(" %s", &s.registers[r])
						}
					}
					fmt.Println()
				}
			}

			// Move arguments to registers.
			// First, if an arg must be in a specific register and it is already
			// in place, keep it.
			args = append(args[:0], make([]*Value, len(v.Args))...)
			for i, a := range v.Args {
				if !s.values[a.ID].needReg {
					args[i] = a
				}
			}
			for _, i := range regspec.inputs {
				mask := i.regs
				if countRegs(mask) == 1 && mask&s.values[v.Args[i.idx].ID].regs != 0 {
					args[i.idx] = s.allocValToReg(v.Args[i.idx], mask, true, v.Pos)
				}
			}
			// Then, if an arg must be in a specific register and that
			// register is free, allocate that one. Otherwise when processing
			// another input we may kick a value into the free register, which
			// then will be kicked out again.
			// This is a common case for passing-in-register arguments for
			// function calls.
			for {
				freed := false
				for _, i := range regspec.inputs {
					if args[i.idx] != nil {
						continue // already allocated
					}
					mask := i.regs
					if countRegs(mask) == 1 && mask&^s.used != 0 {
						args[i.idx] = s.allocValToReg(v.Args[i.idx], mask, true, v.Pos)
						// If the input is in other registers that will be clobbered by v,
						// or the input is dead, free the registers. This may make room
						// for other inputs.
						oldregs := s.values[v.Args[i.idx].ID].regs
						if oldregs&^regspec.clobbers == 0 || !s.liveAfterCurrentInstruction(v.Args[i.idx]) {
							s.freeRegs(oldregs &^ mask &^ s.nospill)
							freed = true
						}
					}
				}
				if !freed {
					break
				}
			}
			// Last, allocate remaining ones, in an ordering defined
			// by the register specification (most constrained first).
			for _, i := range regspec.inputs {
				if args[i.idx] != nil {
					continue // already allocated
				}
				mask := i.regs
				if mask&s.values[v.Args[i.idx].ID].regs == 0 {
					// Need a new register for the input.
					mask &= s.allocatable
					mask &^= s.nospill
					// Used desired register if available.
					if i.idx < 3 {
						for _, r := range dinfo[idx].in[i.idx] {
							if r != noRegister && (mask&^s.used)>>r&1 != 0 {
								// Desired register is allowed and unused.
								mask = regMask(1) << r
								break
							}
						}
					}
					// Avoid registers we're saving for other values.
					if mask&^desired.avoid != 0 {
						mask &^= desired.avoid
					}
				}
				args[i.idx] = s.allocValToReg(v.Args[i.idx], mask, true, v.Pos)
			}

			// If the output clobbers the input register, make sure we have
			// at least two copies of the input register so we don't
			// have to reload the value from the spill location.
			if opcodeTable[v.Op].resultInArg0 {
				var m regMask
				if !s.liveAfterCurrentInstruction(v.Args[0]) {
					// arg0 is dead.  We can clobber its register.
					goto ok
				}
				if opcodeTable[v.Op].commutative && !s.liveAfterCurrentInstruction(v.Args[1]) {
					args[0], args[1] = args[1], args[0]
					goto ok
				}
				if s.values[v.Args[0].ID].rematerializeable {
					// We can rematerialize the input, don't worry about clobbering it.
					goto ok
				}
				if opcodeTable[v.Op].commutative && s.values[v.Args[1].ID].rematerializeable {
					args[0], args[1] = args[1], args[0]
					goto ok
				}
				if countRegs(s.values[v.Args[0].ID].regs) >= 2 {
					// we have at least 2 copies of arg0.  We can afford to clobber one.
					goto ok
				}
				if opcodeTable[v.Op].commutative && countRegs(s.values[v.Args[1].ID].regs) >= 2 {
					args[0], args[1] = args[1], args[0]
					goto ok
				}

				// We can't overwrite arg0 (or arg1, if commutative).  So we
				// need to make a copy of an input so we have a register we can modify.

				// Possible new registers to copy into.
				m = s.compatRegs(v.Args[0].Type) &^ s.used
				if m == 0 {
					// No free registers.  In this case we'll just clobber
					// an input and future uses of that input must use a restore.
					// TODO(khr): We should really do this like allocReg does it,
					// spilling the value with the most distant next use.
					goto ok
				}

				// Try to move an input to the desired output, if allowed.
				for _, r := range dinfo[idx].out {
					if r != noRegister && (m&regspec.outputs[0].regs)>>r&1 != 0 {
						m = regMask(1) << r
						args[0] = s.allocValToReg(v.Args[0], m, true, v.Pos)
						// Note: we update args[0] so the instruction will
						// use the register copy we just made.
						goto ok
					}
				}
				// Try to copy input to its desired location & use its old
				// location as the result register.
				for _, r := range dinfo[idx].in[0] {
					if r != noRegister && m>>r&1 != 0 {
						m = regMask(1) << r
						c := s.allocValToReg(v.Args[0], m, true, v.Pos)
						s.copies[c] = false
						// Note: no update to args[0] so the instruction will
						// use the original copy.
						goto ok
					}
				}
				if opcodeTable[v.Op].commutative {
					for _, r := range dinfo[idx].in[1] {
						if r != noRegister && m>>r&1 != 0 {
							m = regMask(1) << r
							c := s.allocValToReg(v.Args[1], m, true, v.Pos)
							s.copies[c] = false
							args[0], args[1] = args[1], args[0]
							goto ok
						}
					}
				}

				// Avoid future fixed uses if we can.
				if m&^desired.avoid != 0 {
					m &^= desired.avoid
				}
				// Save input 0 to a new register so we can clobber it.
				c := s.allocValToReg(v.Args[0], m, true, v.Pos)
				s.copies[c] = false

				// Normally we use the register of the old copy of input 0 as the target.
				// However, if input 0 is already in its desired register then we use
				// the register of the new copy instead.
				if regspec.outputs[0].regs>>s.f.getHome(c.ID).(*Register).num&1 != 0 {
					if rp, ok := s.f.getHome(args[0].ID).(*Register); ok {
						r := register(rp.num)
						for _, r2 := range dinfo[idx].in[0] {
							if r == r2 {
								args[0] = c
								break
							}
						}
					}
				}
			}

		ok:
			// Pick a temporary register if needed.
			// It should be distinct from all the input registers, so we
			// allocate it after all the input registers, but before
			// the input registers are freed via advanceUses below.
			// (Not all instructions need that distinct part, but it is conservative.)
			// We also ensure it is not any of the single-choice output registers.
			if opcodeTable[v.Op].needIntTemp {
				m := s.allocatable & s.f.Config.gpRegMask
				for _, out := range regspec.outputs {
					if countRegs(out.regs) == 1 {
						m &^= out.regs
					}
				}
				if m&^desired.avoid&^s.nospill != 0 {
					m &^= desired.avoid
				}
				tmpReg = s.allocReg(m, &tmpVal)
				s.nospill |= regMask(1) << tmpReg
			}

			// Now that all args are in regs, we're ready to issue the value itself.
			// Before we pick a register for the output value, allow input registers
			// to be deallocated. We do this here so that the output can use the
			// same register as a dying input.
			if !opcodeTable[v.Op].resultNotInArgs {
				s.tmpused = s.nospill
				s.nospill = 0
				s.advanceUses(v) // frees any registers holding args that are no longer live
			}

			// Dump any registers which will be clobbered
			if s.doClobber && v.Op.IsCall() {
				// clobber registers that are marked as clobber in regmask, but
				// don't clobber inputs.
				s.clobberRegs(regspec.clobbers &^ s.tmpused &^ s.nospill)
			}
			s.freeRegs(regspec.clobbers)
			s.tmpused |= regspec.clobbers

			// Pick registers for outputs.
			{
				outRegs := noRegisters // TODO if this is costly, hoist and clear incrementally below.
				maxOutIdx := -1
				var used regMask
				if tmpReg != noRegister {
					// Ensure output registers are distinct from the temporary register.
					// (Not all instructions need that distinct part, but it is conservative.)
					used |= regMask(1) << tmpReg
				}
				for _, out := range regspec.outputs {
					if out.regs == 0 {
						continue
					}
					mask := out.regs & s.allocatable &^ used
					if mask == 0 {
						s.f.Fatalf("can't find any output register %s", v.LongString())
					}
					if opcodeTable[v.Op].resultInArg0 && out.idx == 0 {
						if !opcodeTable[v.Op].commutative {
							// Output must use the same register as input 0.
							r := register(s.f.getHome(args[0].ID).(*Register).num)
							if mask>>r&1 == 0 {
								s.f.Fatalf("resultInArg0 value's input %v cannot be an output of %s", s.f.getHome(args[0].ID).(*Register), v.LongString())
							}
							mask = regMask(1) << r
						} else {
							// Output must use the same register as input 0 or 1.
							r0 := register(s.f.getHome(args[0].ID).(*Register).num)
							r1 := register(s.f.getHome(args[1].ID).(*Register).num)
							// Check r0 and r1 for desired output register.
							found := false
							for _, r := range dinfo[idx].out {
								if (r == r0 || r == r1) && (mask&^s.used)>>r&1 != 0 {
									mask = regMask(1) << r
									found = true
									if r == r1 {
										args[0], args[1] = args[1], args[0]
									}
									break
								}
							}
							if !found {
								// Neither are desired, pick r0.
								mask = regMask(1) << r0
							}
						}
					}
					if out.idx == 0 { // desired registers only apply to the first element of a tuple result
						for _, r := range dinfo[idx].out {
							if r != noRegister && (mask&^s.used)>>r&1 != 0 {
								// Desired register is allowed and unused.
								mask = regMask(1) << r
								break
							}
						}
					}
					// Avoid registers we're saving for other values.
					if mask&^desired.avoid&^s.nospill&^s.used != 0 {
						mask &^= desired.avoid
					}
					r := s.allocReg(mask, v)
					if out.idx > maxOutIdx {
						maxOutIdx = out.idx
					}
					outRegs[out.idx] = r
					used |= regMask(1) << r
					s.tmpused |= regMask(1) << r
				}
				// Record register choices
				if v.Type.IsTuple() {
					var outLocs LocPair
					if r := outRegs[0]; r != noRegister {
						outLocs[0] = &s.registers[r]
					}
					if r := outRegs[1]; r != noRegister {
						outLocs[1] = &s.registers[r]
					}
					s.f.setHome(v, outLocs)
					// Note that subsequent SelectX instructions will do the assignReg calls.
				} else if v.Type.IsResults() {
					// preallocate outLocs to the right size, which is maxOutIdx+1
					outLocs := make(LocResults, maxOutIdx+1, maxOutIdx+1)
					for i := 0; i <= maxOutIdx; i++ {
						if r := outRegs[i]; r != noRegister {
							outLocs[i] = &s.registers[r]
						}
					}
					s.f.setHome(v, outLocs)
				} else {
					if r := outRegs[0]; r != noRegister {
						s.assignReg(r, v, v)
					}
				}
				if tmpReg != noRegister {
					// Remember the temp register allocation, if any.
					if s.f.tempRegs == nil {
						s.f.tempRegs = map[ID]*Register{}
					}
					s.f.tempRegs[v.ID] = &s.registers[tmpReg]
				}
			}

			// deallocate dead args, if we have not done so
			if opcodeTable[v.Op].resultNotInArgs {
				s.nospill = 0
				s.advanceUses(v) // frees any registers holding args that are no longer live
			}
			s.tmpused = 0

			// Issue the Value itself.
			for i, a := range args {
				v.SetArg(i, a) // use register version of arguments
			}
			b.Values = append(b.Values, v)
			s.dropIfUnused(v)
		}

		// Copy the control values - we need this so we can reduce the
		// uses property of these values later.
		controls := append(make([]*Value, 0, 2), b.ControlValues()...)

		// Load control values into registers.
		for i, v := range b.ControlValues() {
			if !s.values[v.ID].needReg {
				continue
			}
			if s.f.pass.debug > regDebug {
				fmt.Printf("  processing control %s\n", v.LongString())
			}
			// We assume that a control input can be passed in any
			// type-compatible register. If this turns out not to be true,
			// we'll need to introduce a regspec for a block's control value.
			b.ReplaceControl(i, s.allocValToReg(v, s.compatRegs(v.Type), false, b.Pos))
		}

		// Reduce the uses of the control values once registers have been loaded.
		// This loop is equivalent to the advanceUses method.
		for _, v := range controls {
			vi := &s.values[v.ID]
			if !vi.needReg {
				continue
			}
			// Remove this use from the uses list.
			u := vi.uses
			vi.uses = u.next
			if u.next == nil {
				s.freeRegs(vi.regs) // value is dead
			}
			u.next = s.freeUseRecords
			s.freeUseRecords = u
		}

		// If we are approaching a merge point and we are the primary
		// predecessor of it, find live values that we use soon after
		// the merge point and promote them to registers now.
		if len(b.Succs) == 1 {
			if s.f.Config.hasGReg && s.regs[s.GReg].v != nil {
				s.freeReg(s.GReg) // Spill value in G register before any merge.
			}
			// For this to be worthwhile, the loop must have no calls in it.
			top := b.Succs[0].b
			loop := s.loopnest.b2l[top.ID]
			if loop == nil || loop.header != top || loop.containsUnavoidableCall {
				goto badloop
			}

			// TODO: sort by distance, pick the closest ones?
			for _, live := range s.live[b.ID] {
				if live.dist >= unlikelyDistance {
					// Don't preload anything live after the loop.
					continue
				}
				vid := live.ID
				vi := &s.values[vid]
				if vi.regs != 0 {
					continue
				}
				if vi.rematerializeable {
					continue
				}
				v := s.orig[vid]
				m := s.compatRegs(v.Type) &^ s.used
				// Used desired register if available.
			outerloop:
				for _, e := range desired.entries {
					if e.ID != v.ID {
						continue
					}
					for _, r := range e.regs {
						if r != noRegister && m>>r&1 != 0 {
							m = regMask(1) << r
							break outerloop
						}
					}
				}
				if m&^desired.avoid != 0 {
					m &^= desired.avoid
				}
				if m != 0 {
					s.allocValToReg(v, m, false, b.Pos)
				}
			}
		}
	badloop:
		;

		// Save end-of-block register state.
		// First count how many, this cuts allocations in half.
		k := 0
		for r := register(0); r < s.numRegs; r++ {
			v := s.regs[r].v
			if v == nil {
				continue
			}
			k++
		}
		regList := make([]endReg, 0, k)
		for r := register(0); r < s.numRegs; r++ {
			v := s.regs[r].v
			if v == nil {
				continue
			}
			regList = append(regList, endReg{r, v, s.regs[r].c})
		}
		s.endRegs[b.ID] = regList

		if checkEnabled {
			regValLiveSet.clear()
			for _, x := range s.live[b.ID] {
				regValLiveSet.add(x.ID)
			}
			for r := register(0); r < s.numRegs; r++ {
				v := s.regs[r].v
				if v == nil {
					continue
				}
				if !regValLiveSet.contains(v.ID) {
					s.f.Fatalf("val %s is in reg but not live at end of %s", v, b)
				}
			}
		}

		// If a value is live at the end of the block and
		// isn't in a register, generate a use for the spill location.
		// We need to remember this information so that
		// the liveness analysis in stackalloc is correct.
		for _, e := range s.live[b.ID] {
			vi := &s.values[e.ID]
			if vi.regs != 0 {
				// in a register, we'll use that source for the merge.
				continue
			}
			if vi.rematerializeable {
				// we'll rematerialize during the merge.
				continue
			}
			if s.f.pass.debug > regDebug {
				fmt.Printf("live-at-end spill for %s at %s\n", s.orig[e.ID], b)
			}
			spill := s.makeSpill(s.orig[e.ID], b)
			s.spillLive[b.ID] = append(s.spillLive[b.ID], spill.ID)
		}

		// Clear any final uses.
		// All that is left should be the pseudo-uses added for values which
		// are live at the end of b.
		for _, e := range s.live[b.ID] {
			u := s.values[e.ID].uses
			if u == nil {
				f.Fatalf("live at end, no uses v%d", e.ID)
			}
			if u.next != nil {
				f.Fatalf("live at end, too many uses v%d", e.ID)
			}
			s.values[e.ID].uses = nil
			u.next = s.freeUseRecords
			s.freeUseRecords = u
		}

		// allocReg may have dropped registers from startRegsMask that
		// aren't actually needed in startRegs. Synchronize back to
		// startRegs.
		//
		// This must be done before placing spills, which will look at
		// startRegs to decide if a block is a valid block for a spill.
		if c := countRegs(s.startRegsMask); c != len(s.startRegs[b.ID]) {
			regs := make([]startReg, 0, c)
			for _, sr := range s.startRegs[b.ID] {
				if s.startRegsMask&(regMask(1)<<sr.r) == 0 {
					continue
				}
				regs = append(regs, sr)
			}
			s.startRegs[b.ID] = regs
		}
	}

	// Decide where the spills we generated will go.
	s.placeSpills()

	// Anything that didn't get a register gets a stack location here.
	// (StoreReg, stack-based phis, inputs, ...)
	stacklive := stackalloc(s.f, s.spillLive)

	// Fix up all merge edges.
	s.shuffle(stacklive)

	// Erase any copies we never used.
	// Also, an unused copy might be the only use of another copy,
	// so continue erasing until we reach a fixed point.
	for {
		progress := false
		for c, used := range s.copies {
			if !used && c.Uses == 0 {
				if s.f.pass.debug > regDebug {
					fmt.Printf("delete copied value %s\n", c.LongString())
				}
				c.resetArgs()
				f.freeValue(c)
				delete(s.copies, c)
				progress = true
			}
		}
		if !progress {
			break
		}
	}

	for _, b := range s.visitOrder {
		i := 0
		for _, v := range b.Values {
			if v.Op == OpInvalid {
				continue
			}
			b.Values[i] = v
			i++
		}
		b.Values = b.Values[:i]
	}
}

func (s *regAllocState) placeSpills() {
	mustBeFirst := func(op Op) bool {
		return op.isLoweredGetClosurePtr() || op == OpPhi || op == OpArgIntReg || op == OpArgFloatReg
	}

	// Start maps block IDs to the list of spills
	// that go at the start of the block (but after any phis).
	start := map[ID][]*Value{}
	// After maps value IDs to the list of spills
	// that go immediately after that value ID.
	after := map[ID][]*Value{}

	for i := range s.values {
		vi := s.values[i]
		spill := vi.spill
		if spill == nil {
			continue
		}
		if spill.Block != nil {
			// Some spills are already fully set up,
			// like OpArgs and stack-based phis.
			continue
		}
		v := s.orig[i]

		// Walk down the dominator tree looking for a good place to
		// put the spill of v.  At the start "best" is the best place
		// we have found so far.
		// TODO: find a way to make this O(1) without arbitrary cutoffs.
		if v == nil {
			panic(fmt.Errorf("nil v, s.orig[%d], vi = %v, spill = %s", i, vi, spill.LongString()))
		}
		best := v.Block
		bestArg := v
		var bestDepth int16
		if l := s.loopnest.b2l[best.ID]; l != nil {
			bestDepth = l.depth
		}
		b := best
		const maxSpillSearch = 100
		for i := 0; i < maxSpillSearch; i++ {
			// Find the child of b in the dominator tree which
			// dominates all restores.
			p := b
			b = nil
			for c := s.sdom.Child(p); c != nil && i < maxSpillSearch; c, i = s.sdom.Sibling(c), i+1 {
				if s.sdom[c.ID].entry <= vi.restoreMin && s.sdom[c.ID].exit >= vi.restoreMax {
					// c also dominates all restores.  Walk down into c.
					b = c
					break
				}
			}
			if b == nil {
				// Ran out of blocks which dominate all restores.
				break
			}

			var depth int16
			if l := s.loopnest.b2l[b.ID]; l != nil {
				depth = l.depth
			}
			if depth > bestDepth {
				// Don't push the spill into a deeper loop.
				continue
			}

			// If v is in a register at the start of b, we can
			// place the spill here (after the phis).
			if len(b.Preds) == 1 {
				for _, e := range s.endRegs[b.Preds[0].b
```