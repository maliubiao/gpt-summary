Response: Let's break down the thought process for analyzing this Go code snippet and generating the detailed explanation.

**1. Initial Skim and Identification of Core Purpose:**

The first step is a quick read-through to grasp the high-level goal. Keywords like "MergeLocals," "stack-allocated variables," "overlapped," "share a stack slot," and mentions of `ssagen.AllocFrame` immediately suggest that this code is about optimizing stack usage by allowing certain local variables to occupy the same memory location at different times.

**2. Data Structures as Clues:**

The `MergeLocalsState` struct is crucial. Its fields, `vars` and `partition`, are explicitly documented. The documentation and example provided for `partition` are extremely helpful in understanding the core data representation of the merging process. The `candRegion` and `cstate` structs suggest a multi-stage process involving identifying candidates and maintaining state during analysis.

**3. Function Signatures and Return Values:**

The `MergeLocals` function is the entry point. Its signature (`func MergeLocals(fn *ir.Func, f *ssa.Func) *MergeLocalsState`) tells us it takes function representations from the compiler's intermediate representation (`ir.Func`) and static single assignment form (`ssa.Func`) and returns the `MergeLocalsState`. This reinforces that it's part of the compilation process.

**4. Deeper Dive into Key Functions:**

* **`collectMergeCandidates`:**  This function's name is self-explanatory. The code within it iterates through declarations (`cs.fn.Dcl`), filters based on `n.Used()` and `ssa.IsMergeCandidate(n)`, and sorts the potential candidates. This highlights the initial selection criteria. The call to `cs.genRegions` and `cs.populateIndirectUseTable` indicates a refinement process.

* **`computeIntervals`:** This function name suggests it calculates the "lifetimes" of the candidate variables. The use of `liveness` package, `IntervalsBuilder`, and the backwards sweep through the instructions strongly support this interpretation. The comments about "upwards exposed uses" and "kills" solidify the liveness analysis aspect.

* **`performMerging`:** This function takes the calculated intervals and applies a merging strategy. The call to `cs.mergeVisitRegion` and the logic within it (using a `bitvec` to track used slots) demonstrates the core merging algorithm.

* **Helper functions:**  Functions like `Subsumed`, `IsLeader`, `Leader`, `Followers`, and `EstSavings` on `MergeLocalsState` provide ways to query the result of the merging process. The `check` method suggests internal consistency validation.

**5. Connecting to Go Language Features:**

Based on the core purpose and the use of compiler-internal data structures (`ir`, `ssa`), it's highly likely this code implements an optimization related to **local variable allocation on the stack**. The goal is to reduce stack frame size.

**6. Constructing the Go Code Example (Hypothetical):**

To illustrate the merging, a simple function with two local variables that don't interfere with each other's lifetimes is a good starting point. The example should demonstrate how two distinct variables might end up sharing the same stack space. This requires making assumptions about the liveness analysis results.

**7. Inferring Command-Line Arguments:**

The presence of `base.Debug.MergeLocalsTrace`, `base.Debug.MergeLocalsDumpFunc`, `base.Debug.MergeLocalsHash`, and `base.Debug.MergeLocalsHTrace` strongly suggests command-line flags for controlling the debugging output and behavior of this optimization. The names themselves are quite descriptive.

**8. Identifying Potential Pitfalls:**

The "leader" concept is key. The code explicitly enforces constraints on the size, pointer-ness, and alignment of follower variables relative to the leader. A common mistake could be assuming any two non-overlapping variables can be merged, without considering these type compatibility requirements.

**9. Iterative Refinement and Fact-Checking:**

Throughout the analysis, it's essential to re-read comments and code, ensuring the interpretation is consistent with the implementation. For example, understanding the meaning of "subsumed" requires careful attention to the `partition` map structure.

**Self-Correction Example during Analysis:**

Initially, I might have focused solely on lifetime non-overlap as the merging criterion. However, seeing the checks in `nextRegion` (size and alignment) and the checks in `mls.check()` (size, pointer-ness, alignment) for followers compared to the leader corrected my understanding. This highlighted that type compatibility is a crucial aspect, not just lifetime.

By following these steps, combining code inspection with understanding of compiler optimizations and Go language principles, a comprehensive and accurate explanation of the code's functionality can be generated.
这段代码是Go语言编译器 `cmd/compile` 的一部分，位于 `internal/liveness` 包中，文件名是 `mergelocals.go`。它的主要功能是**分析Go函数中局部变量的生命周期，并确定哪些局部变量可以安全地共享同一个栈空间，从而优化栈帧的大小**。这是一种栈空间复用（stack slot reuse）的优化技术。

以下是代码中涉及的功能点的详细解释：

**1. 核心功能：局部变量的栈空间合并/重叠 (Stack Slot Merging/Overlapping)**

   - **目标:** 减少函数栈帧的大小，提高内存利用率。
   - **原理:**  如果两个或多个局部变量的生命周期不重叠，它们可以共享同一个栈空间。
   - **实现:**  `MergeLocals` 函数是入口，它分析函数的 SSA 表示 (`ssa.Func`)，并返回一个 `MergeLocalsState` 对象，描述了哪些变量可以合并。

**2. `MergeLocalsState` 结构体:**

   -  该结构体封装了栈空间合并分析的结果。
   -  `vars []*ir.Name`:  一个参与合并的局部变量列表。
   -  `partition map[*ir.Name][]int`:  一个映射，键是局部变量，值是一个整数切片，表示与该变量共享栈空间的其它变量在 `vars` 列表中的索引。切片中的第一个元素是“leader”变量的索引，其它元素是共享同一个栈空间的“follower”变量的索引。

**3. `cstate` 结构体:**

   -  在分析过程中使用的临时状态信息，分析完成后可以丢弃。
   -  包含了函数信息 (`fn`, `f`)、活跃性分析结果 (`lv`)、候选合并的变量列表 (`cands`)、变量到槽位的映射 (`nameToSlot`)、兼容变量的区域信息 (`regions`)、间接向上暴露使用信息 (`indirectUE`)、区间信息 (`ivs`) 等。

**4. `MergeLocals(fn *ir.Func, f *ssa.Func) *MergeLocalsState` 函数:**

   -  这是进行栈空间合并分析的主要函数。
   -  **`collectMergeCandidates()`:** 收集可以作为合并候选的局部变量。标准包括：是自动分配的 (`AUTO`)，被使用过 (`n.Used()`)，并且满足 `ssa.IsMergeCandidate(n)` 的条件（通常是非地址可取的）。
   -  **活跃性分析 (`newliveness`)**:  计算每个候选变量在程序执行过程中的活跃区间。`conservativeWrites = true` 表示写操作也被视为使用，这对于栈空间合并至关重要。
   -  **`computeIntervals()`:** 基于活跃性分析结果和块效应，计算每个候选变量的生命周期区间 (`Intervals`)。
   -  **`performMerging()`:**  在每个兼容的变量区域内，执行实际的合并操作，生成 `MergeLocalsState`。

**5. 辅助方法 (`MergeLocalsState` 的方法):**

   -  **`Subsumed(n *ir.Name) bool`:** 判断变量 `n` 是否是被合并的（是某个合并组的 follower，而不是 leader）。
   -  **`IsLeader(n *ir.Name) bool`:** 判断变量 `n` 是否是其所在合并组的 leader。
   -  **`Leader(n *ir.Name) *ir.Name`:** 返回变量 `n` 所在合并组的 leader 变量。
   -  **`Followers(n *ir.Name, tmp []*ir.Name) []*ir.Name`:** 返回变量 `n` (作为 leader) 的所有 follower 变量。
   -  **`EstSavings() (int, int)`:** 估计通过栈空间合并节省的栈空间大小（分别计算非指针类型和指针类型的节省）。
   -  **`check() error`:**  对 `MergeLocalsState` 的内部状态进行一致性检查，用于调试。
   -  **`String() string`:**  返回 `MergeLocalsState` 的字符串表示，方便查看合并结果。

**6. `collectMergeCandidates()` 的细节:**

   -  **筛选候选:**  只考虑 `AUTO` 类型的局部变量，并且被使用过的。`ssa.IsMergeCandidate` 函数会根据变量的属性（例如是否被取地址）来判断是否可以作为合并的候选。
   -  **排序:**  候选变量会根据是否包含指针、大小和名称进行排序。排序的目的是为了更有效地进行合并。
   -  **`genRegions()`:**  将候选变量列表划分为若干个“区域”，同一区域内的变量在类型和大小上是兼容的，有可能进行合并。
   -  **`setupHashBisection()`:**  如果启用了基于哈希的调试，可以根据哈希值选择性地跳过某些变量的合并分析，用于隔离和调试问题。
   -  **`populateIndirectUseTable()`:**  处理间接使用的情况。例如，如果一个变量的地址被取出并通过指针间接访问，这也会影响其生命周期。

**7. `computeIntervals()` 的细节:**

   -  **反向扫描:**  从函数的末尾开始，反向遍历基本块和指令。
   -  **活跃性边界:**  在基本块的边界处，根据 `liveout` 信息更新变量的活跃状态。
   -  **指令效应:**  对于每条指令，分析其对变量活跃状态的影响：
      -  **`uevar` (upwards exposed use):**  变量被使用，并且在当前指令前不是活跃的。
      -  **`varkill`:** 变量被定义（例如赋值），结束了之前的活跃区间。
   -  **间接使用:**  考虑通过指针等方式的间接使用。

**8. `performMerging()` 的细节:**

   -  **贪心策略:**  在每个兼容变量的区域内，使用贪心算法进行合并。
   -  **Leader 选择:**  选择区域内的第一个变量作为 leader。
   -  **Follower 合并:**  遍历后续变量，如果其生命周期与 leader 的生命周期不重叠，则将其添加到 leader 的合并组中。
   -  **约束:**  被合并的 follower 变量的大小不能大于 leader 变量，并且需要满足指针和对齐方面的约束。

**通过 Go 代码举例说明:**

假设有以下 Go 代码片段：

```go
package main

func foo() {
	var a int
	a = 10
	println(a)

	var b string
	b = "hello"
	println(b)
}
```

**假设的输入 (SSA 表示):**  （简化表示，实际 SSA 更复杂）

```
b1:
  v1 = ConstInt 10
  a = v1
  println(a)
  goto b2

b2:
  v2 = ConstString "hello"
  b = v2
  println(b)
  ret
```

**分析:**

- 变量 `a` 的生命周期从 `a = v1` 开始，到 `println(a)` 结束。
- 变量 `b` 的生命周期从 `b = v2` 开始，到 `println(b)` 结束。
- `a` 和 `b` 的生命周期不重叠。

**假设的 `MergeLocalsState` 输出:**

```
vars: [a, b]
partition: a -> [0, 1], b -> [0, 1]
```

或者，更准确地，根据 leader 的定义：

```
vars: [a, b]
partition: a -> [0], b -> [1]  // 如果没有实际的合并发生，每个变量都是自己的 leader
```

**如果 `a` 和 `b` 可以合并 (例如，类型和大小兼容，且生命周期不重叠):**

```
vars: [a, b]
partition: a -> [0, 1], b -> [0, 1]
```

这里，`a` 是 leader (索引 0)，`b` 是 follower (索引 1)，它们共享同一个栈空间。

**命令行参数的具体处理:**

代码中使用了 `base.Debug` 包来获取调试相关的命令行参数，例如：

- **`-d=mergelocalstrace=N`:**  设置合并局部变量的调试追踪级别。更高的 `N` 值会输出更详细的调试信息。
- **`-d=mergelocalsdumpfunc=函数名后缀`:**  如果函数的名称后缀匹配，则在合并局部变量分析前后转储该函数的 SSA 表示。
- **`-d=mergelocalshash=哈希值`:**  使用哈希值来选择性地启用或禁用某些局部变量的合并分析，用于调试特定的情况。
- **`-d=mergelocalshtrace=N`:** 仅当通过哈希选择了至少两个候选变量时，才启用调试追踪。

这些参数通常通过 `go tool compile` 命令的 `-d` 标志传递，例如：

```bash
go tool compile -d=mergelocalstrace=2 mypackage.go
```

**使用者易犯错的点:**

作为编译器开发者，理解这段代码至关重要。对于普通的 Go 语言使用者，他们通常不需要直接与这段代码交互。然而，理解栈空间合并的原理可以帮助他们编写更高效的代码，虽然这种影响通常是编译器自动处理的。

**总结:**

`mergelocals.go` 中的代码实现了 Go 编译器的栈空间合并优化，通过分析局部变量的生命周期，使得不冲突的变量可以共享栈空间，从而减少函数的栈帧大小，提高程序的内存效率。它涉及到活跃性分析、区间计算和贪心合并算法等技术。

### 提示词
```
这是路径为go/src/cmd/compile/internal/liveness/mergelocals.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package liveness

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/bitvec"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/ssa"
	"cmd/internal/src"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// MergeLocalsState encapsulates information about which AUTO
// (stack-allocated) variables within a function can be safely
// merged/overlapped, e.g. share a stack slot with some other auto).
// An instance of MergeLocalsState is produced by MergeLocals() below
// and then consumed in ssagen.AllocFrame. The map 'partition'
// contains entries of the form <N,SL> where N is an *ir.Name and SL
// is a slice holding the indices (within 'vars') of other variables
// that share the same slot, specifically the slot of the first
// element in the partition, which we'll call the "leader". For
// example, if a function contains five variables where v1/v2/v3 are
// safe to overlap and v4/v5 are safe to overlap, the MergeLocalsState
// content might look like
//
//	vars: [v1, v2, v3, v4, v5]
//	partition: v1 -> [1, 0, 2], v2 -> [1, 0, 2], v3 -> [1, 0, 2]
//	           v4 -> [3, 4], v5 -> [3, 4]
//
// A nil MergeLocalsState indicates that no local variables meet the
// necessary criteria for overlap.
type MergeLocalsState struct {
	// contains auto vars that participate in overlapping
	vars []*ir.Name
	// maps auto variable to overlap partition
	partition map[*ir.Name][]int
}

// candRegion is a sub-range (start, end) corresponding to an interval
// [st,en] within the list of candidate variables.
type candRegion struct {
	st, en int
}

// cstate holds state information we'll need during the analysis
// phase of stack slot merging but can be discarded when the analysis
// is done.
type cstate struct {
	fn             *ir.Func
	f              *ssa.Func
	lv             *liveness
	cands          []*ir.Name
	nameToSlot     map[*ir.Name]int32
	regions        []candRegion
	indirectUE     map[ssa.ID][]*ir.Name
	ivs            []Intervals
	hashDeselected map[*ir.Name]bool
	trace          int // debug trace level
}

// MergeLocals analyzes the specified ssa function f to determine which
// of its auto variables can safely share the same stack slot, returning
// a state object that describes how the overlap should be done.
func MergeLocals(fn *ir.Func, f *ssa.Func) *MergeLocalsState {

	// Create a container object for useful state info and then
	// call collectMergeCandidates to see if there are vars suitable
	// for stack slot merging.
	cs := &cstate{
		fn:    fn,
		f:     f,
		trace: base.Debug.MergeLocalsTrace,
	}
	cs.collectMergeCandidates()
	if len(cs.regions) == 0 {
		return nil
	}

	// Kick off liveness analysis.
	//
	// If we have a local variable such as "r2" below that's written
	// but then not read, something like:
	//
	//      vardef r1
	//      r1.x = ...
	//      vardef r2
	//      r2.x = 0
	//      r2.y = ...
	//      <call foo>
	//      // no subsequent use of r2
	//      ... = r1.x
	//
	// then for the purpose of calculating stack maps at the call, we
	// can ignore "r2" completely during liveness analysis for stack
	// maps, however for stack slock merging we most definitely want
	// to treat the writes as "uses".
	cs.lv = newliveness(fn, f, cs.cands, cs.nameToSlot, 0)
	cs.lv.conservativeWrites = true
	cs.lv.prologue()
	cs.lv.solve()

	// Compute intervals for each candidate based on the liveness and
	// on block effects.
	cs.computeIntervals()

	// Perform merging within each region of the candidates list.
	rv := cs.performMerging()
	if err := rv.check(); err != nil {
		base.FatalfAt(fn.Pos(), "invalid mergelocals state: %v", err)
	}
	return rv
}

// Subsumed returns whether variable n is subsumed, e.g. appears
// in an overlap position but is not the leader in that partition.
func (mls *MergeLocalsState) Subsumed(n *ir.Name) bool {
	if sl, ok := mls.partition[n]; ok && mls.vars[sl[0]] != n {
		return true
	}
	return false
}

// IsLeader returns whether a variable n is the leader (first element)
// in a sharing partition.
func (mls *MergeLocalsState) IsLeader(n *ir.Name) bool {
	if sl, ok := mls.partition[n]; ok && mls.vars[sl[0]] == n {
		return true
	}
	return false
}

// Leader returns the leader variable for subsumed var n.
func (mls *MergeLocalsState) Leader(n *ir.Name) *ir.Name {
	if sl, ok := mls.partition[n]; ok {
		if mls.vars[sl[0]] == n {
			panic("variable is not subsumed")
		}
		return mls.vars[sl[0]]
	}
	panic("not a merge candidate")
}

// Followers writes a list of the followers for leader n into the slice tmp.
func (mls *MergeLocalsState) Followers(n *ir.Name, tmp []*ir.Name) []*ir.Name {
	tmp = tmp[:0]
	sl, ok := mls.partition[n]
	if !ok {
		panic("no entry for leader")
	}
	if mls.vars[sl[0]] != n {
		panic("followers invoked on subsumed var")
	}
	for _, k := range sl[1:] {
		tmp = append(tmp, mls.vars[k])
	}
	slices.SortStableFunc(tmp, func(a, b *ir.Name) int {
		return strings.Compare(a.Sym().Name, b.Sym().Name)
	})
	return tmp
}

// EstSavings returns the estimated reduction in stack size (number of bytes) for
// the given merge locals state via a pair of ints, the first for non-pointer types and the second for pointer types.
func (mls *MergeLocalsState) EstSavings() (int, int) {
	totnp := 0
	totp := 0
	for n := range mls.partition {
		if mls.Subsumed(n) {
			sz := int(n.Type().Size())
			if n.Type().HasPointers() {
				totp += sz
			} else {
				totnp += sz
			}
		}
	}
	return totnp, totp
}

// check tests for various inconsistencies and problems in mls,
// returning an error if any problems are found.
func (mls *MergeLocalsState) check() error {
	if mls == nil {
		return nil
	}
	used := make(map[int]bool)
	seenv := make(map[*ir.Name]int)
	for ii, v := range mls.vars {
		if prev, ok := seenv[v]; ok {
			return fmt.Errorf("duplicate var %q in vslots: %d and %d\n",
				v.Sym().Name, ii, prev)
		}
		seenv[v] = ii
	}
	for k, sl := range mls.partition {
		// length of slice value needs to be more than 1
		if len(sl) < 2 {
			return fmt.Errorf("k=%q v=%+v slice len %d invalid",
				k.Sym().Name, sl, len(sl))
		}
		// values in the slice need to be var indices
		for i, v := range sl {
			if v < 0 || v > len(mls.vars)-1 {
				return fmt.Errorf("k=%q v=+%v slpos %d vslot %d out of range of m.v", k.Sym().Name, sl, i, v)
			}
		}
	}
	for k, sl := range mls.partition {
		foundk := false
		for i, v := range sl {
			vv := mls.vars[v]
			if i == 0 {
				if !mls.IsLeader(vv) {
					return fmt.Errorf("k=%s v=+%v slpos 0 vslot %d IsLeader(%q) is false should be true", k.Sym().Name, sl, v, vv.Sym().Name)
				}
			} else {
				if !mls.Subsumed(vv) {
					return fmt.Errorf("k=%s v=+%v slpos %d vslot %d Subsumed(%q) is false should be true", k.Sym().Name, sl, i, v, vv.Sym().Name)
				}
				if mls.Leader(vv) != mls.vars[sl[0]] {
					return fmt.Errorf("k=%s v=+%v slpos %d vslot %d Leader(%q) got %v want %v", k.Sym().Name, sl, i, v, vv.Sym().Name, mls.Leader(vv), mls.vars[sl[0]])
				}
			}
			if vv == k {
				foundk = true
				if used[v] {
					return fmt.Errorf("k=%s v=+%v val slice used violation at slpos %d vslot %d", k.Sym().Name, sl, i, v)
				}
				used[v] = true
			}
		}
		if !foundk {
			return fmt.Errorf("k=%s v=+%v slice value missing k", k.Sym().Name, sl)
		}
		vl := mls.vars[sl[0]]
		for _, v := range sl[1:] {
			vv := mls.vars[v]
			if vv.Type().Size() > vl.Type().Size() {
				return fmt.Errorf("k=%s v=+%v follower %s size %d larger than leader %s size %d", k.Sym().Name, sl, vv.Sym().Name, vv.Type().Size(), vl.Sym().Name, vl.Type().Size())
			}
			if vv.Type().HasPointers() && !vl.Type().HasPointers() {
				return fmt.Errorf("k=%s v=+%v follower %s hasptr=true but leader %s hasptr=false", k.Sym().Name, sl, vv.Sym().Name, vl.Sym().Name)
			}
			if vv.Type().Alignment() > vl.Type().Alignment() {
				return fmt.Errorf("k=%s v=+%v follower %s align %d greater than leader %s align %d", k.Sym().Name, sl, vv.Sym().Name, vv.Type().Alignment(), vl.Sym().Name, vl.Type().Alignment())
			}
		}
	}
	for i := range used {
		if !used[i] {
			return fmt.Errorf("pos %d var %q unused", i, mls.vars[i])
		}
	}
	return nil
}

func (mls *MergeLocalsState) String() string {
	var leaders []*ir.Name
	for n, sl := range mls.partition {
		if n == mls.vars[sl[0]] {
			leaders = append(leaders, n)
		}
	}
	slices.SortFunc(leaders, func(a, b *ir.Name) int {
		return strings.Compare(a.Sym().Name, b.Sym().Name)
	})
	var sb strings.Builder
	for _, n := range leaders {
		sb.WriteString(n.Sym().Name + ":")
		sl := mls.partition[n]
		for _, k := range sl[1:] {
			n := mls.vars[k]
			sb.WriteString(" " + n.Sym().Name)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// collectMergeCandidates visits all of the AUTO vars declared in
// function fn and identifies a list of candidate variables for
// merging / overlapping. On return the "cands" field of cs will be
// filled in with our set of potentially overlappable candidate
// variables, the "regions" field will hold regions/sequence of
// compatible vars within the candidates list, "nameToSlot" field will
// be populated, and the "indirectUE" field will be filled in with
// information about indirect upwards-exposed uses in the func.
func (cs *cstate) collectMergeCandidates() {
	var cands []*ir.Name

	// Collect up the available set of appropriate AUTOs in the
	// function as a first step, and bail if we have fewer than
	// two candidates.
	for _, n := range cs.fn.Dcl {
		if !n.Used() {
			continue
		}
		if !ssa.IsMergeCandidate(n) {
			continue
		}
		cands = append(cands, n)
	}
	if len(cands) < 2 {
		return
	}

	// Sort by pointerness, size, and then name.
	sort.SliceStable(cands, func(i, j int) bool {
		return nameLess(cands[i], cands[j])
	})

	if cs.trace > 1 {
		fmt.Fprintf(os.Stderr, "=-= raw cand list for func %v:\n", cs.fn)
		for i := range cands {
			dumpCand(cands[i], i)
		}
	}

	// Now generate an initial pruned candidate list and regions list.
	// This may be empty if we don't have enough compatible candidates.
	initial, _ := cs.genRegions(cands)
	if len(initial) < 2 {
		return
	}

	// Set up for hash bisection if enabled.
	cs.setupHashBisection(initial)

	// Create and populate an indirect use table that we'll use
	// during interval construction. As part of this process we may
	// wind up tossing out additional candidates, so check to make
	// sure we still have something to work with.
	cs.cands, cs.regions = cs.populateIndirectUseTable(initial)
	if len(cs.cands) < 2 {
		return
	}

	// At this point we have a final pruned set of candidates and a
	// corresponding set of regions for the candidates. Build a
	// name-to-slot map for the candidates.
	cs.nameToSlot = make(map[*ir.Name]int32)
	for i, n := range cs.cands {
		cs.nameToSlot[n] = int32(i)
	}

	if cs.trace > 1 {
		fmt.Fprintf(os.Stderr, "=-= pruned candidate list for fn %v:\n", cs.fn)
		for i := range cs.cands {
			dumpCand(cs.cands[i], i)
		}
	}
}

// genRegions generates a set of regions within cands corresponding
// to potentially overlappable/mergeable variables.
func (cs *cstate) genRegions(cands []*ir.Name) ([]*ir.Name, []candRegion) {
	var pruned []*ir.Name
	var regions []candRegion
	st := 0
	for {
		en := nextRegion(cands, st)
		if en == -1 {
			break
		}
		if st == en {
			// region has just one element, we can skip it
			st++
			continue
		}
		pst := len(pruned)
		pen := pst + (en - st)
		if cs.trace > 1 {
			fmt.Fprintf(os.Stderr, "=-= addregion st=%d en=%d: add part %d -> %d\n", st, en, pst, pen)
		}

		// non-empty region, add to pruned
		pruned = append(pruned, cands[st:en+1]...)
		regions = append(regions, candRegion{st: pst, en: pen})
		st = en + 1
	}
	if len(pruned) < 2 {
		return nil, nil
	}
	return pruned, regions
}

func (cs *cstate) dumpFunc() {
	fmt.Fprintf(os.Stderr, "=-= mergelocalsdumpfunc %v:\n", cs.fn)
	ii := 0
	for k, b := range cs.f.Blocks {
		fmt.Fprintf(os.Stderr, "b%d:\n", k)
		for _, v := range b.Values {
			pos := base.Ctxt.PosTable.Pos(v.Pos)
			fmt.Fprintf(os.Stderr, "=-= %d L%d|C%d %s\n", ii, pos.RelLine(), pos.RelCol(), v.LongString())
			ii++
		}
	}
}

func (cs *cstate) dumpFuncIfSelected() {
	if base.Debug.MergeLocalsDumpFunc == "" {
		return
	}
	if !strings.HasSuffix(fmt.Sprintf("%v", cs.fn),
		base.Debug.MergeLocalsDumpFunc) {
		return
	}
	cs.dumpFunc()
}

// setupHashBisection checks to see if any of the candidate
// variables have been de-selected by our hash debug. Here
// we also implement the -d=mergelocalshtrace flag, which turns
// on debug tracing only if we have at least two candidates
// selected by the hash debug for this function.
func (cs *cstate) setupHashBisection(cands []*ir.Name) {
	if base.Debug.MergeLocalsHash == "" {
		return
	}
	deselected := make(map[*ir.Name]bool)
	selCount := 0
	for _, cand := range cands {
		if !base.MergeLocalsHash.MatchPosWithInfo(cand.Pos(), "mergelocals", nil) {
			deselected[cand] = true
		} else {
			deselected[cand] = false
			selCount++
		}
	}
	if selCount < len(cands) {
		cs.hashDeselected = deselected
	}
	if base.Debug.MergeLocalsHTrace != 0 && selCount >= 2 {
		cs.trace = base.Debug.MergeLocalsHTrace
	}
}

// populateIndirectUseTable creates and populates the "indirectUE" table
// within cs by doing some additional analysis of how the vars in
// cands are accessed in the function.
//
// It is possible to have situations where a given ir.Name is
// non-address-taken at the source level, but whose address is
// materialized in order to accommodate the needs of
// architecture-dependent operations or one sort or another (examples
// include things like LoweredZero/DuffZero, etc). The issue here is
// that the SymAddr op will show up as touching a variable of
// interest, but the subsequent memory op will not. This is generally
// not an issue for computing whether something is live across a call,
// but it is problematic for collecting the more fine-grained live
// interval info that drives stack slot merging.
//
// To handle this problem, make a forward pass over each basic block
// looking for instructions of the form vK := SymAddr(N) where N is a
// raw candidate. Create an entry in a map at that point from vK to
// its use count. Continue the walk, looking for uses of vK: when we
// see one, record it in a side table as an upwards exposed use of N.
// Each time we see a use, decrement the use count in the map, and if
// we hit zero, remove the map entry. If we hit the end of the basic
// block and we still have map entries, then evict the name in
// question from the candidate set.
func (cs *cstate) populateIndirectUseTable(cands []*ir.Name) ([]*ir.Name, []candRegion) {

	// main indirect UE table, this is what we're producing in this func
	indirectUE := make(map[ssa.ID][]*ir.Name)

	// this map holds the current set of candidates; the set may
	// shrink if we have to evict any candidates.
	rawcands := make(map[*ir.Name]struct{})

	// maps ssa value V to the ir.Name it is taking the addr of,
	// plus a count of the uses we've seen of V during a block walk.
	pendingUses := make(map[ssa.ID]nameCount)

	// A temporary indirect UE tab just for the current block
	// being processed; used to help with evictions.
	blockIndirectUE := make(map[ssa.ID][]*ir.Name)

	// temporary map used to record evictions in a given block.
	evicted := make(map[*ir.Name]bool)
	for _, n := range cands {
		rawcands[n] = struct{}{}
	}
	for k := 0; k < len(cs.f.Blocks); k++ {
		clear(pendingUses)
		clear(blockIndirectUE)
		b := cs.f.Blocks[k]
		for _, v := range b.Values {
			if n, e := affectedVar(v); n != nil {
				if _, ok := rawcands[n]; ok {
					if e&ssa.SymAddr != 0 && v.Uses != 0 {
						// we're taking the address of candidate var n
						if _, ok := pendingUses[v.ID]; ok {
							// should never happen
							base.FatalfAt(v.Pos, "internal error: apparent multiple defs for SSA value %d", v.ID)
						}
						// Stash an entry in pendingUses recording
						// that we took the address of "n" via this
						// val.
						pendingUses[v.ID] = nameCount{n: n, count: v.Uses}
						if cs.trace > 2 {
							fmt.Fprintf(os.Stderr, "=-= SymAddr(%s) on %s\n",
								n.Sym().Name, v.LongString())
						}
					}
				}
			}
			for _, arg := range v.Args {
				if nc, ok := pendingUses[arg.ID]; ok {
					// We found a use of some value that took the
					// address of nc.n. Record this inst as a
					// potential indirect use.
					if cs.trace > 2 {
						fmt.Fprintf(os.Stderr, "=-= add indirectUE(%s) count=%d on %s\n", nc.n.Sym().Name, nc.count, v.LongString())
					}
					blockIndirectUE[v.ID] = append(blockIndirectUE[v.ID], nc.n)
					nc.count--
					if nc.count == 0 {
						// That was the last use of the value. Clean
						// up the entry in pendingUses.
						if cs.trace > 2 {
							fmt.Fprintf(os.Stderr, "=-= last use of v%d\n",
								arg.ID)
						}
						delete(pendingUses, arg.ID)
					} else {
						// Not the last use; record the decremented
						// use count and move on.
						pendingUses[arg.ID] = nc
					}
				}
			}
		}

		// We've reached the end of this basic block: if we have any
		// leftover entries in pendingUses, then evict the
		// corresponding names from the candidate set. The idea here
		// is that if we materialized the address of some local and
		// that value is flowing out of the block off somewhere else,
		// we're going to treat that local as truly address-taken and
		// not have it be a merge candidate.
		clear(evicted)
		if len(pendingUses) != 0 {
			for id, nc := range pendingUses {
				if cs.trace > 2 {
					fmt.Fprintf(os.Stderr, "=-= evicting %q due to pendingUse %d count %d\n", nc.n.Sym().Name, id, nc.count)
				}
				delete(rawcands, nc.n)
				evicted[nc.n] = true
			}
		}
		// Copy entries from blockIndirectUE into final indirectUE. Skip
		// anything that we evicted in the loop above.
		for id, sl := range blockIndirectUE {
			for _, n := range sl {
				if evicted[n] {
					continue
				}
				indirectUE[id] = append(indirectUE[id], n)
				if cs.trace > 2 {
					fmt.Fprintf(os.Stderr, "=-= add final indUE v%d name %s\n", id, n.Sym().Name)
				}
			}
		}
	}
	if len(rawcands) < 2 {
		return nil, nil
	}
	cs.indirectUE = indirectUE
	if cs.trace > 2 {
		fmt.Fprintf(os.Stderr, "=-= iuetab:\n")
		ids := make([]ssa.ID, 0, len(indirectUE))
		for k := range indirectUE {
			ids = append(ids, k)
		}
		slices.Sort(ids)
		for _, id := range ids {
			fmt.Fprintf(os.Stderr, "  v%d:", id)
			for _, n := range indirectUE[id] {
				fmt.Fprintf(os.Stderr, " %s", n.Sym().Name)
			}
			fmt.Fprintf(os.Stderr, "\n")
		}
	}

	pruned := cands[:0]
	for k := range rawcands {
		pruned = append(pruned, k)
	}
	sort.Slice(pruned, func(i, j int) bool {
		return nameLess(pruned[i], pruned[j])
	})
	var regions []candRegion
	pruned, regions = cs.genRegions(pruned)
	if len(pruned) < 2 {
		return nil, nil
	}
	return pruned, regions
}

type nameCount struct {
	n     *ir.Name
	count int32
}

// nameLess compares ci with cj to see if ci should be less than cj in
// a relative ordering of candidate variables. This is used to sort
// vars by pointerness (variables with pointers first), then in order
// of decreasing alignment, then by decreasing size. We are assuming a
// merging algorithm that merges later entries in the list into
// earlier entries. An example ordered candidate list produced by
// nameLess:
//
//	idx   name    type       align    size
//	0:    abc     [10]*int   8        80
//	1:    xyz     [9]*int    8        72
//	2:    qrs     [2]*int    8        16
//	3:    tuv     [9]int     8        72
//	4:    wxy     [9]int32   4        36
//	5:    jkl     [8]int32   4        32
func nameLess(ci, cj *ir.Name) bool {
	if ci.Type().HasPointers() != cj.Type().HasPointers() {
		return ci.Type().HasPointers()
	}
	if ci.Type().Alignment() != cj.Type().Alignment() {
		return cj.Type().Alignment() < ci.Type().Alignment()
	}
	if ci.Type().Size() != cj.Type().Size() {
		return cj.Type().Size() < ci.Type().Size()
	}
	if ci.Sym().Name != cj.Sym().Name {
		return ci.Sym().Name < cj.Sym().Name
	}
	return fmt.Sprintf("%v", ci.Pos()) < fmt.Sprintf("%v", cj.Pos())
}

// nextRegion starts at location idx and walks forward in the cands
// slice looking for variables that are "compatible" (potentially
// overlappable, in the sense that they could potentially share the
// stack slot of cands[idx]); it returns the end of the new region
// (range of compatible variables starting at idx).
func nextRegion(cands []*ir.Name, idx int) int {
	n := len(cands)
	if idx >= n {
		return -1
	}
	c0 := cands[idx]
	szprev := c0.Type().Size()
	alnprev := c0.Type().Alignment()
	for j := idx + 1; j < n; j++ {
		cj := cands[j]
		szj := cj.Type().Size()
		if szj > szprev {
			return j - 1
		}
		alnj := cj.Type().Alignment()
		if alnj > alnprev {
			return j - 1
		}
		szprev = szj
		alnprev = alnj
	}
	return n - 1
}

// mergeVisitRegion tries to perform overlapping of variables with a
// given subrange of cands described by st and en (indices into our
// candidate var list), where the variables within this range have
// already been determined to be compatible with respect to type,
// size, etc. Overlapping is done in a greedy fashion: we select the
// first element in the st->en range, then walk the rest of the
// elements adding in vars whose lifetimes don't overlap with the
// first element, then repeat the process until we run out of work.
// Ordering of the candidates within the region [st,en] is important;
// within the list the assumption is that if we overlap two variables
// X and Y where X precedes Y in the list, we need to make X the
// "leader" (keep X's slot and set Y's frame offset to X's) as opposed
// to the other way around, since it's possible that Y is smaller in
// size than X.
func (cs *cstate) mergeVisitRegion(mls *MergeLocalsState, st, en int) {
	if cs.trace > 1 {
		fmt.Fprintf(os.Stderr, "=-= mergeVisitRegion(st=%d, en=%d)\n", st, en)
	}
	n := en - st + 1
	used := bitvec.New(int32(n))

	nxt := func(slot int) int {
		for c := slot - st; c < n; c++ {
			if used.Get(int32(c)) {
				continue
			}
			return c + st
		}
		return -1
	}

	navail := n
	cands := cs.cands
	ivs := cs.ivs
	if cs.trace > 1 {
		fmt.Fprintf(os.Stderr, "  =-= navail = %d\n", navail)
	}
	for navail >= 2 {
		leader := nxt(st)
		used.Set(int32(leader - st))
		navail--

		if cs.trace > 1 {
			fmt.Fprintf(os.Stderr, "  =-= begin leader %d used=%s\n", leader,
				used.String())
		}
		elems := []int{leader}
		lints := ivs[leader]

		for succ := nxt(leader + 1); succ != -1; succ = nxt(succ + 1) {

			// Skip if de-selected by merge locals hash.
			if cs.hashDeselected != nil && cs.hashDeselected[cands[succ]] {
				continue
			}
			// Skip if already used.
			if used.Get(int32(succ - st)) {
				continue
			}
			if cs.trace > 1 {
				fmt.Fprintf(os.Stderr, "  =-= overlap of %d[%v] {%s} with %d[%v] {%s} is: %v\n", leader, cands[leader], lints.String(), succ, cands[succ], ivs[succ].String(), lints.Overlaps(ivs[succ]))
			}

			// Can we overlap leader with this var?
			if lints.Overlaps(ivs[succ]) {
				continue
			} else {
				// Add to overlap set.
				elems = append(elems, succ)
				lints = lints.Merge(ivs[succ])
			}
		}
		if len(elems) > 1 {
			// We found some things to overlap with leader. Add the
			// candidate elements to "vars" and update "partition".
			off := len(mls.vars)
			sl := make([]int, len(elems))
			for i, candslot := range elems {
				sl[i] = off + i
				mls.vars = append(mls.vars, cands[candslot])
				mls.partition[cands[candslot]] = sl
			}
			navail -= (len(elems) - 1)
			for i := range elems {
				used.Set(int32(elems[i] - st))
			}
			if cs.trace > 1 {
				fmt.Fprintf(os.Stderr, "=-= overlapping %+v:\n", sl)
				for i := range sl {
					dumpCand(mls.vars[sl[i]], sl[i])
				}
				for i, v := range elems {
					fmt.Fprintf(os.Stderr, "=-= %d: sl=%d %s\n", i, v, ivs[v])
				}
			}
		}
	}
}

// performMerging carries out variable merging within each of the
// candidate ranges in regions, returning a state object
// that describes the variable overlaps.
func (cs *cstate) performMerging() *MergeLocalsState {
	cands := cs.cands

	mls := &MergeLocalsState{
		partition: make(map[*ir.Name][]int),
	}

	// Dump state before attempting overlap.
	if cs.trace > 1 {
		fmt.Fprintf(os.Stderr, "=-= cands live before overlap:\n")
		for i := range cands {
			c := cands[i]
			fmt.Fprintf(os.Stderr, "%d: %v sz=%d ivs=%s\n",
				i, c.Sym().Name, c.Type().Size(), cs.ivs[i].String())
		}
		fmt.Fprintf(os.Stderr, "=-= regions (%d): ", len(cs.regions))
		for _, cr := range cs.regions {
			fmt.Fprintf(os.Stderr, " [%d,%d]", cr.st, cr.en)
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	// Apply a greedy merge/overlap strategy within each region
	// of compatible variables.
	for _, cr := range cs.regions {
		cs.mergeVisitRegion(mls, cr.st, cr.en)
	}
	if len(mls.vars) == 0 {
		return nil
	}
	return mls
}

// computeIntervals performs a backwards sweep over the instructions
// of the function we're compiling, building up an Intervals object
// for each candidate variable by looking for upwards exposed uses
// and kills.
func (cs *cstate) computeIntervals() {
	lv := cs.lv
	ibuilders := make([]IntervalsBuilder, len(cs.cands))
	nvars := int32(len(lv.vars))
	liveout := bitvec.New(nvars)

	cs.dumpFuncIfSelected()

	// Count instructions.
	ninstr := 0
	for _, b := range lv.f.Blocks {
		ninstr += len(b.Values)
	}
	// current instruction index during backwards walk
	iidx := ninstr - 1

	// Make a backwards pass over all blocks
	for k := len(lv.f.Blocks) - 1; k >= 0; k-- {
		b := lv.f.Blocks[k]
		be := lv.blockEffects(b)

		if cs.trace > 2 {
			fmt.Fprintf(os.Stderr, "=-= liveout from tail of b%d: ", k)
			for j := range lv.vars {
				if be.liveout.Get(int32(j)) {
					fmt.Fprintf(os.Stderr, " %q", lv.vars[j].Sym().Name)
				}
			}
			fmt.Fprintf(os.Stderr, "\n")
		}

		// Take into account effects taking place at end of this basic
		// block by comparing our current live set with liveout for
		// the block. If a given var was not live before and is now
		// becoming live we need to mark this transition with a
		// builder "Live" call; similarly if a var was live before and
		// is now no longer live, we need a "Kill" call.
		for j := range lv.vars {
			isLive := liveout.Get(int32(j))
			blockLiveOut := be.liveout.Get(int32(j))
			if isLive {
				if !blockLiveOut {
					if cs.trace > 2 {
						fmt.Fprintf(os.Stderr, "=+= at instr %d block boundary kill of %v\n", iidx, lv.vars[j])
					}
					ibuilders[j].Kill(iidx)
				}
			} else if blockLiveOut {
				if cs.trace > 2 {
					fmt.Fprintf(os.Stderr, "=+= at block-end instr %d %v becomes live\n",
						iidx, lv.vars[j])
				}
				ibuilders[j].Live(iidx)
			}
		}

		// Set our working "currently live" set to the previously
		// computed live out set for the block.
		liveout.Copy(be.liveout)

		// Now walk backwards through this block.
		for i := len(b.Values) - 1; i >= 0; i-- {
			v := b.Values[i]

			if cs.trace > 2 {
				fmt.Fprintf(os.Stderr, "=-= b%d instr %d: %s\n", k, iidx, v.LongString())
			}

			// Update liveness based on what we see happening in this
			// instruction.
			pos, e := lv.valueEffects(v)
			becomeslive := e&uevar != 0
			iskilled := e&varkill != 0
			if becomeslive && iskilled {
				// we do not ever expect to see both a kill and an
				// upwards exposed use given our size constraints.
				panic("should never happen")
			}
			if iskilled && liveout.Get(pos) {
				ibuilders[pos].Kill(iidx)
				liveout.Unset(pos)
				if cs.trace > 2 {
					fmt.Fprintf(os.Stderr, "=+= at instr %d kill of %v\n",
						iidx, lv.vars[pos])
				}
			} else if becomeslive && !liveout.Get(pos) {
				ibuilders[pos].Live(iidx)
				liveout.Set(pos)
				if cs.trace > 2 {
					fmt.Fprintf(os.Stderr, "=+= at instr %d upwards-exposed use of %v\n",
						iidx, lv.vars[pos])
				}
			}

			if cs.indirectUE != nil {
				// Now handle "indirect" upwards-exposed uses.
				ues := cs.indirectUE[v.ID]
				for _, n := range ues {
					if pos, ok := lv.idx[n]; ok {
						if !liveout.Get(pos) {
							ibuilders[pos].Live(iidx)
							liveout.Set(pos)
							if cs.trace > 2 {
								fmt.Fprintf(os.Stderr, "=+= at instr %d v%d indirect upwards-exposed use of %v\n", iidx, v.ID, lv.vars[pos])
							}
						}
					}
				}
			}
			iidx--
		}

		// This check disabled for now due to the way scheduling works
		// for ops that materialize values of local variables. For
		// many architecture we have rewrite rules of this form:
		//
		// (LocalAddr <t> {sym} base mem) && t.Elem().HasPointers() => (MOVDaddr {sym} (SPanchored base mem))
		// (LocalAddr <t> {sym} base _)  && !t.Elem().HasPointers() => (MOVDaddr {sym} base)
		//
		// which are designed to ensure that if you have a pointerful
		// variable "abc" sequence
		//
		//    v30 = VarDef <mem> {abc} v21
		//    v31 = LocalAddr <*SB> {abc} v2 v30
		//    v32 = Zero <mem> {SB} [2056] v31 v30
		//
		// this will be lowered into
		//
		//    v30 = VarDef <mem> {sb} v21
		//   v106 = SPanchored <uintptr> v2 v30
		//    v31 = MOVDaddr <*SB> {sb} v106
		//     v3 = DUFFZERO <mem> [2056] v31 v30
		//
		// Note the SPanchored: this ensures that the scheduler won't
		// move the MOVDaddr earlier than the vardef. With a variable
		// "xyz" that has no pointers, however, if we start with
		//
		//    v66 = VarDef <mem> {t2} v65
		//    v67 = LocalAddr <*T> {t2} v2 v66
		//    v68 = Zero <mem> {T} [2056] v67 v66
		//
		// we might lower to
		//
		//    v66 = VarDef <mem> {t2} v65
		//    v29 = MOVDaddr <*T> {t2} [2032] v2
		//    v43 = LoweredZero <mem> v67 v29 v66
		//    v68 = Zero [2056] v2 v43
		//
		// where that MOVDaddr can float around arbitrarily, meaning
		// that we may see an upwards-exposed use to it before the
		// VarDef.
		//
		// One avenue to restoring the check below would be to change
		// the rewrite rules to something like
		//
		// (LocalAddr <t> {sym} base mem) && (t.Elem().HasPointers() || isMergeCandidate(t) => (MOVDaddr {sym} (SPanchored base mem))
		//
		// however that change will have to be carefully evaluated,
		// since it would constrain the scheduler for _all_ LocalAddr
		// ops for potential merge candidates, even if we don't
		// actually succeed in any overlaps. This will be revisitged in
		// a later CL if possible.
		//
		const checkLiveOnEntry = false
		if checkLiveOnEntry && b == lv.f.Entry {
			for j, v := range lv.vars {
				if liveout.Get(int32(j)) {
					lv.f.Fatalf("%v %L recorded as live on entry",
						lv.fn.Nname, v)
				}
			}
		}
	}
	if iidx != -1 {
		panic("iidx underflow")
	}

	// Finish intervals construction.
	ivs := make([]Intervals, len(cs.cands))
	for i := range cs.cands {
		var err error
		ivs[i], err = ibuilders[i].Finish()
		if err != nil {
			cs.dumpFunc()
			base.FatalfAt(cs.cands[i].Pos(), "interval construct error for var %q in func %q (%d instrs): %v", cs.cands[i].Sym().Name, ir.FuncName(cs.fn), ninstr, err)
		}
	}
	cs.ivs = ivs
}

func fmtFullPos(p src.XPos) string {
	var sb strings.Builder
	sep := ""
	base.Ctxt.AllPos(p, func(pos src.Pos) {
		sb.WriteString(sep)
		sep = "|"
		file := filepath.Base(pos.Filename())
		fmt.Fprintf(&sb, "%s:%d:%d", file, pos.Line(), pos.Col())
	})
	return sb.String()
}

func dumpCand(c *ir.Name, i int) {
	fmt.Fprintf(os.Stderr, " %d: %s %q sz=%d hp=%v align=%d t=%v\n",
		i, fmtFullPos(c.Pos()), c.Sym().Name, c.Type().Size(),
		c.Type().HasPointers(), c.Type().Alignment(), c.Type())
}

// for unit testing only.
func MakeMergeLocalsState(partition map[*ir.Name][]int, vars []*ir.Name) (*MergeLocalsState, error) {
	mls := &MergeLocalsState{partition: partition, vars: vars}
	if err := mls.check(); err != nil {
		return nil, err
	}
	return mls, nil
}
```