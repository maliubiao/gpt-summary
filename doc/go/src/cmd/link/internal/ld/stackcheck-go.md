Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Initial Understanding - The Goal:** The first thing I notice is the file path: `go/src/cmd/link/internal/ld/stackcheck.go`. This immediately tells me it's part of the Go linker (`cmd/link`) and is specifically related to stack checking during the linking process. The package name `ld` confirms this. The comments at the beginning reinforce this: it's about checking stack space, particularly for "nosplit" functions.

2. **Core Data Structures:** I then scan for the main data structures. `stackCheck` is the central struct. I look at its fields:
    * `ctxt *Link`:  Likely a context object holding linker-wide information.
    * `ldr *loader.Loader`:  Interface for accessing loaded object code information (symbols, relocations, etc.).
    * `morestack loader.Sym`:  A symbol representing the `runtime.morestack` function (crucial for stack growth).
    * `callSize int`: The size of a function call's overhead on the stack.
    * `height map[loader.Sym]int16`:  Key: symbol, Value: maximum stack usage by that function and its callees *without* a stack split. This is the core of the analysis.
    * `graph map[loader.Sym][]stackCheckEdge`:  Call graph of the functions involved. Only built in a second pass when errors are detected.

3. **Key Functions:**  Next, I look for the primary functions:
    * `doStackCheck()`: The main entry point for the stack checking logic. It initializes a `stackCheck` object, sets a stack limit, performs an initial check, and if that fails, builds a call graph and reports errors.
    * `newStackCheck()`: Constructor for the `stackCheck` struct. Handles initialization, including determining `callSize`.
    * `symName()`: Helper function to get a human-readable name for a symbol.
    * `check()`:  Calculates and caches the stack height for a given symbol. It detects cycles using `stackCheckCycle`. It calls `computeHeight`.
    * `computeHeight()`:  The core logic for determining a function's stack height by analyzing its instructions (specifically stack pointer adjustments and calls). It handles special cases like `morestack` and external functions.
    * `findRoots()`:  Identifies the root nodes in the call graph (functions not called by others). Used for error reporting.
    * `report()`:  Traverses the call graph to report stack overflow errors, printing the call chain that exceeds the limit.

4. **Flow of Execution (doStackCheck):** I try to follow the flow of `doStackCheck`:
    * Initializes `stackCheck`.
    * Calculates the stack limit based on `objabi.StackNosplit` and architecture.
    * Iterates through all text symbols (functions) and calls `sc.check()` to get their stack heights.
    * If any function exceeds the limit:
        * Re-runs the check, but this time builds the call graph (`sc.graph`).
        * Finds the root functions using `findRoots()`.
        * Iterates through the roots and calls `sc.report()` to print the error chains.

5. **Important Concepts:**  I identify some key concepts:
    * **Nosplit Functions:** Functions marked as `nosplit` must guarantee they won't overflow the stack without a check. This is the main focus of the analysis.
    * **Stack Splitting:**  The `runtime.morestack` function is crucial. It ensures enough stack space before a function call. Splittable functions call this.
    * **Call Graph:**  The `graph` field and related logic are for detailed error reporting.
    * **Cycles:** The code handles potential infinite recursion in the call graph using the `stackCheckCycle` sentinel.
    * **Indirect Calls:** Special handling for indirect calls (function pointers, closures).

6. **Inferring Go Functionality:** Based on the analysis, I can infer that this code is implementing the Go runtime's mechanism to prevent stack overflows, particularly in situations where functions are marked as not needing stack checks (e.g., for performance reasons or because they are very low-level).

7. **Code Example (Illustrative):** To illustrate, I can construct a simplified Go example demonstrating the concept of `nosplit` and how this stack checker would interact:

   ```go
   package main

   import "runtime"

   //go:nosplit
   func leafFunc() {
       var x [1000]byte // Small stack allocation
       _ = x
   }

   //go:nosplit
   func nosplitCall() {
       var y [2000]byte // Larger stack allocation
       _ = y
       leafFunc()
   }

   func main() {
       nosplitCall()
   }
   ```
   The stack checker would analyze `nosplitCall` and `leafFunc` to ensure their combined stack usage doesn't exceed the limit.

8. **Command-Line Parameters:**  I notice the usage of `*flagRace` and `*flagDebugNosplit`. I recognize these as likely command-line flags used during the `go build` or `go link` process. I can speculate about their functions (race detector impacting stack limits, debug flag enabling more verbose output).

9. **Common Mistakes:** I think about potential developer errors: marking a function as `//go:nosplit` when it or its callees might use a significant amount of stack. Or creating a `nosplit` function that recursively calls itself without bound.

10. **Refinement and Structuring:** Finally, I organize my findings into the requested categories: functionality, inferred Go feature, code example, command-line parameters, and common mistakes. I ensure the language is clear and concise. I review the original code snippet to make sure my analysis aligns with its logic. For example, noticing the two-pass approach in `doStackCheck` (first pass for speed, second for detailed error reporting).

This iterative process of understanding the context, identifying key components, tracing execution flow, and connecting it to broader Go concepts allows for a comprehensive analysis of the code snippet.
这段Go语言代码是Go链接器（`cmd/link`）的一部分，其主要功能是执行**栈溢出检查（Stack Overflow Check）**，特别是针对被标记为 `//go:nosplit` 的函数。这类函数在执行时不进行栈溢出检查，因此链接器需要静态地分析它们的栈使用情况，以确保不会导致栈溢出。

以下是代码的具体功能分解：

**1. 核心目标：防止 nosplit 函数栈溢出**

这段代码的核心目标是确保在没有栈溢出检查的情况下运行的函数（`nosplit` 函数）不会导致程序崩溃。它通过分析函数的调用关系和栈帧大小来实现这一目标。

**2. `stackCheck` 结构体：存储检查所需的状态**

`stackCheck` 结构体用于存储执行栈检查所需的上下文信息：

*   `ctxt *Link`:  链接器的上下文信息。
*   `ldr *loader.Loader`:  用于加载和访问程序符号信息的加载器。
*   `morestack loader.Sym`:  表示 `runtime.morestack` 函数的符号。这个函数用于扩展栈空间，是普通可分割栈函数调用的入口。
*   `callSize int`:  表示函数调用的开销，即 `CALL` 指令在栈上增加的字节数。这取决于目标架构。
*   `height map[loader.Sym]int16`:  一个映射，用于记录每个函数及其调用链在没有栈分割检查的情况下可以增加的最大栈空间大小。
*   `graph map[loader.Sym][]stackCheckEdge`:  一个图，表示函数调用关系。只有在第一次检查发现超出限制的函数时，才会构建这个图，用于生成更详细的错误报告。

**3. `stackCheckEdge` 结构体：表示调用图中的边**

`stackCheckEdge` 结构体表示调用图中的一条边，描述了一个函数调用另一个函数时栈空间的增长情况：

*   `growth int`:  调用目标函数时栈空间增长的字节数。
*   `target loader.Sym`:  被调用函数的符号。如果是局部栈增长或叶子函数，则为 0。

**4. `doStackCheck()` 函数：执行主要的栈检查流程**

`doStackCheck()` 函数是执行栈检查的主要入口点：

*   **初始化 `stackCheck` 结构体：** 创建一个新的 `stackCheck` 实例。
*   **计算栈空间限制：**  根据 `objabi.StackNosplit(*flagRace)` 获取 `nosplit` 函数可用的栈空间限制，并减去函数调用的开销 (`callSize`) 以及可能的额外开销（例如 ARM64 架构需要额外的 8 字节保存 FP）。
*   **第一次检查（快速检查）：**  遍历所有文本段中的函数，调用 `sc.check()` 计算每个函数的栈高度。如果任何函数的栈高度超过限制，则记录下来。
*   **第二次检查（详细检查）：** 如果第一次检查发现有函数超出限制，则创建一个新的 `stackCheck` 实例，并设置 `graph` 字段为非 `nil`，以便记录调用图。重新检查超出限制的函数，这次会构建调用图。
*   **查找调用图的根节点：**  调用 `sc.findRoots()` 找到调用图中没有被其他函数调用的根节点。
*   **报告错误路径：**  对于每个根节点，调用 `sc.report()` 函数，沿着调用链向下遍历，找出导致栈溢出的具体路径，并打印详细的错误信息。

**5. `newStackCheck()` 函数：创建并初始化 `stackCheck` 实例**

`newStackCheck()` 函数负责创建并初始化 `stackCheck` 结构体，包括计算 `callSize`。

**6. `symName()` 函数：获取符号的名称**

`symName()` 函数用于获取给定符号的易读名称，用于错误报告和调试输出。

**7. `check()` 函数：计算和缓存函数的栈高度**

`check()` 函数是计算函数栈高度的核心函数。它使用 `height` 映射来缓存已经计算过的函数的栈高度，并使用 `stackCheckCycle` 来检测调用环路。它调用 `computeHeight()` 来实际计算栈高度。

**8. `computeHeight()` 函数：实际计算函数的栈高度**

`computeHeight()` 函数负责实际计算给定函数的栈高度：

*   **特殊情况处理：**  对于 `runtime.morestack` 和间接调用 (`stackCheckIndirect`) 进行特殊处理。
*   **忽略外部函数：**  假设外部函数在系统栈上运行，有足够的空间，因此忽略对外部函数的调用。
*   **处理可分割栈函数：**  对于非 `nosplit` 的函数，其栈高度主要取决于调用 `runtime.morestack` 的开销。
*   **处理 `nosplit` 函数：**  对于 `nosplit` 函数，遍历其指令，查找栈指针的调整 (`pcsp`) 和函数调用 (`relocs`)，累积栈空间的增长。

**9. `findRoots()` 函数：查找调用图的根节点**

`findRoots()` 函数用于查找调用图中没有被其他函数调用的根节点。它通过遍历调用图，删除可达的节点，剩下的就是根节点（或环路中的起始节点）。

**10. `report()` 函数：生成详细的栈溢出错误报告**

`report()` 函数用于生成详细的栈溢出错误报告。它递归地遍历调用图，打印导致栈溢出的调用链。它使用 `stackCheckChain` 结构体来跟踪打印过的调用边，以避免重复打印。

**推理 Go 语言功能：静态栈溢出分析**

这段代码实现的是 Go 语言链接器中的**静态栈溢出分析**功能，主要针对 `//go:nosplit` 函数。`//go:nosplit` 告诉编译器，这个函数在执行时不进行栈溢出检查，这通常用于对性能有极致要求的底层代码。然而，这也带来了潜在的风险，如果 `nosplit` 函数或其调用的其他 `nosplit` 函数占用了过多的栈空间，可能会导致栈溢出。

**Go 代码示例：**

```go
package main

import "runtime"

//go:nosplit
func leafFunc() {
	var buf [100]byte
	_ = buf
}

//go:nosplit
func middleFunc() {
	var buf [200]byte
	_ = buf
	leafFunc()
}

//go:nosplit
func topFunc() {
	var buf [300]byte
	_ = buf
	middleFunc()
}

func main() {
	topFunc()
}
```

**假设的输入与输出：**

假设 `objabi.StackNosplit` 的值为 512 字节，`sc.callSize` 为 8 字节。

*   **输入：** 上面的 `main.go` 文件。
*   **第一次检查：**
    *   `leafFunc` 的栈高度：100 字节（局部变量）
    *   `middleFunc` 的栈高度：200 字节（局部变量）+ 8 字节 (调用 `leafFunc`) + 100 字节 (`leafFunc` 的栈高度) = 308 字节
    *   `topFunc` 的栈高度：300 字节（局部变量）+ 8 字节 (调用 `middleFunc`) + 308 字节 (`middleFunc` 的栈高度) = 616 字节
*   **发现超出限制：** `topFunc` 的栈高度 616 字节超过了 512 字节的限制。
*   **第二次检查（构建调用图）：** 构建调用关系图：`topFunc` -> `middleFunc`, `middleFunc` -> `leafFunc`。
*   **输出：**
    ```
    # command-line-arguments
    ./main.go:18: nosplit stack over 512 byte limit
    main.topFunc<0>
        grows 300 bytes, calls main.middleFunc<0>
            grows 200 bytes, calls main.leafFunc<0>
                grows 100 bytes
        64 bytes over limit
    ```

**命令行参数的具体处理：**

*   `*flagRace`:  这是一个布尔类型的标志，通常用于启用 Go 的竞态检测器。在 `doStackCheck` 函数中，它被用来调整 `nosplit` 函数的栈空间限制 (`objabi.StackNosplit(*flagRace)`)。当启用竞态检测时，可能会减少 `nosplit` 函数可用的栈空间，因为竞态检测器需要在栈上存储额外的信息。
*   `*flagDebugNosplit`: 这是一个布尔类型的标志，用于启用 `nosplit` 相关的调试信息。当启用时，`check()` 函数会打印出更详细的关于栈高度计算和调用关系的信息。

**使用者易犯错的点：**

使用者在使用 `//go:nosplit` 时最容易犯的错误是**低估了函数的栈使用量**。以下是一些具体的例子：

1. **在 `nosplit` 函数中声明过大的局部变量：**

    ```go
    //go:nosplit
    func largeLocal() {
        var buf [1024 * 1024]byte // 声明了一个 1MB 的局部变量
        // ...
    }
    ```

    如果 `StackNosplit` 的限制小于 1MB，这段代码将会导致链接时的栈溢出错误。

2. **`nosplit` 函数调用了其他的 `nosplit` 函数，导致栈空间累积超出限制：**

    ```go
    //go:nosplit
    func a() {
        var buf [500]byte
        _ = buf
        b()
    }

    //go:nosplit
    func b() {
        var buf [600]byte
        _ = buf
    }
    ```

    如果 `StackNosplit` 的限制小于 1100 字节，这段代码也会导致错误。

3. **在 `nosplit` 函数中使用了可能导致栈分配的内置函数或操作：** 例如，在 `nosplit` 函数中进行字符串拼接或切片操作，如果编译器没有进行优化，可能会导致意外的栈分配。

**总结：**

这段 `stackcheck.go` 代码是 Go 链接器中一个重要的组成部分，它通过静态分析来确保 `//go:nosplit` 函数不会导致栈溢出，提高了程序的健壮性和安全性。理解这段代码的功能和原理，可以帮助开发者更好地使用 `//go:nosplit` 指令，并避免潜在的栈溢出风险。

### 提示词
```
这是路径为go/src/cmd/link/internal/ld/stackcheck.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ld

import (
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/link/internal/loader"
	"fmt"
	"internal/buildcfg"
	"sort"
	"strings"
)

type stackCheck struct {
	ctxt      *Link
	ldr       *loader.Loader
	morestack loader.Sym
	callSize  int // The number of bytes added by a CALL

	// height records the maximum number of bytes a function and
	// its callees can add to the stack without a split check.
	height map[loader.Sym]int16

	// graph records the out-edges from each symbol. This is only
	// populated on a second pass if the first pass reveals an
	// over-limit function.
	graph map[loader.Sym][]stackCheckEdge
}

type stackCheckEdge struct {
	growth int        // Stack growth in bytes at call to target
	target loader.Sym // 0 for stack growth without a call
}

// stackCheckCycle is a sentinel stored in the height map to detect if
// we've found a cycle. This is effectively an "infinite" stack
// height, so we use the closest value to infinity that we can.
const stackCheckCycle int16 = 1<<15 - 1

// stackCheckIndirect is a sentinel Sym value used to represent the
// target of an indirect/closure call.
const stackCheckIndirect loader.Sym = ^loader.Sym(0)

// doStackCheck walks the call tree to check that there is always
// enough stack space for call frames, especially for a chain of
// nosplit functions.
//
// It walks all functions to accumulate the number of bytes they can
// grow the stack by without a split check and checks this against the
// limit.
func (ctxt *Link) doStackCheck() {
	sc := newStackCheck(ctxt, false)

	// limit is number of bytes a splittable function ensures are
	// available on the stack. If any call chain exceeds this
	// depth, the stack check test fails.
	//
	// The call to morestack in every splittable function ensures
	// that there are at least StackLimit bytes available below SP
	// when morestack returns.
	limit := objabi.StackNosplit(*flagRace) - sc.callSize
	if buildcfg.GOARCH == "arm64" {
		// Need an extra 8 bytes below SP to save FP.
		limit -= 8
	}

	// Compute stack heights without any back-tracking information.
	// This will almost certainly succeed and we can simply
	// return. If it fails, we do a second pass with back-tracking
	// to produce a good error message.
	//
	// This accumulates stack heights bottom-up so it only has to
	// visit every function once.
	var failed []loader.Sym
	for _, s := range ctxt.Textp {
		if sc.check(s) > limit {
			failed = append(failed, s)
		}
	}

	if len(failed) > 0 {
		// Something was over-limit, so now we do the more
		// expensive work to report a good error. First, for
		// the over-limit functions, redo the stack check but
		// record the graph this time.
		sc = newStackCheck(ctxt, true)
		for _, s := range failed {
			sc.check(s)
		}

		// Find the roots of the graph (functions that are not
		// called by any other function).
		roots := sc.findRoots()

		// Find and report all paths that go over the limit.
		// This accumulates stack depths top-down. This is
		// much less efficient because we may have to visit
		// the same function multiple times at different
		// depths, but lets us find all paths.
		for _, root := range roots {
			ctxt.Errorf(root, "nosplit stack over %d byte limit", limit)
			chain := []stackCheckChain{{stackCheckEdge{0, root}, false}}
			sc.report(root, limit, &chain)
		}
	}
}

func newStackCheck(ctxt *Link, graph bool) *stackCheck {
	sc := &stackCheck{
		ctxt:      ctxt,
		ldr:       ctxt.loader,
		morestack: ctxt.loader.Lookup("runtime.morestack", 0),
		height:    make(map[loader.Sym]int16, len(ctxt.Textp)),
	}
	// Compute stack effect of a CALL operation. 0 on LR machines.
	// 1 register pushed on non-LR machines.
	if !ctxt.Arch.HasLR {
		sc.callSize = ctxt.Arch.RegSize
	}

	if graph {
		// We're going to record the call graph.
		sc.graph = make(map[loader.Sym][]stackCheckEdge)
	}

	return sc
}

func (sc *stackCheck) symName(sym loader.Sym) string {
	switch sym {
	case stackCheckIndirect:
		return "indirect"
	case 0:
		return "leaf"
	}
	return fmt.Sprintf("%s<%d>", sc.ldr.SymName(sym), sc.ldr.SymVersion(sym))
}

// check returns the stack height of sym. It populates sc.height and
// sc.graph for sym and every function in its call tree.
func (sc *stackCheck) check(sym loader.Sym) int {
	if h, ok := sc.height[sym]; ok {
		// We've already visited this symbol or we're in a cycle.
		return int(h)
	}
	// Store the sentinel so we can detect cycles.
	sc.height[sym] = stackCheckCycle
	// Compute and record the height and optionally edges.
	h, edges := sc.computeHeight(sym, *flagDebugNosplit || sc.graph != nil)
	if h > int(stackCheckCycle) { // Prevent integer overflow
		h = int(stackCheckCycle)
	}
	sc.height[sym] = int16(h)
	if sc.graph != nil {
		sc.graph[sym] = edges
	}

	if *flagDebugNosplit {
		for _, edge := range edges {
			fmt.Printf("nosplit: %s +%d", sc.symName(sym), edge.growth)
			if edge.target == 0 {
				// Local stack growth or leaf function.
				fmt.Printf("\n")
			} else {
				fmt.Printf(" -> %s\n", sc.symName(edge.target))
			}
		}
	}

	return h
}

// computeHeight returns the stack height of sym. If graph is true, it
// also returns the out-edges of sym.
//
// Caching is applied to this in check. Call check instead of calling
// this directly.
func (sc *stackCheck) computeHeight(sym loader.Sym, graph bool) (int, []stackCheckEdge) {
	ldr := sc.ldr

	// Check special cases.
	if sym == sc.morestack {
		// morestack looks like it calls functions, but they
		// either happen only when already on the system stack
		// (where there is ~infinite space), or after
		// switching to the system stack. Hence, its stack
		// height on the user stack is 0.
		return 0, nil
	}
	if sym == stackCheckIndirect {
		// Assume that indirect/closure calls are always to
		// splittable functions, so they just need enough room
		// to call morestack.
		return sc.callSize, []stackCheckEdge{{sc.callSize, sc.morestack}}
	}

	// Ignore calls to external functions. Assume that these calls
	// are only ever happening on the system stack, where there's
	// plenty of room.
	if ldr.AttrExternal(sym) {
		return 0, nil
	}
	if info := ldr.FuncInfo(sym); !info.Valid() { // also external
		return 0, nil
	}

	// Track the maximum height of this function and, if we're
	// recording the graph, its out-edges.
	var edges []stackCheckEdge
	maxHeight := 0
	ctxt := sc.ctxt
	// addEdge adds a stack growth out of this function to
	// function "target" or, if target == 0, a local stack growth
	// within the function.
	addEdge := func(growth int, target loader.Sym) {
		if graph {
			edges = append(edges, stackCheckEdge{growth, target})
		}
		height := growth
		if target != 0 { // Don't walk into the leaf "edge"
			height += sc.check(target)
		}
		if height > maxHeight {
			maxHeight = height
		}
	}

	if !ldr.IsNoSplit(sym) {
		// Splittable functions start with a call to
		// morestack, after which their height is 0. Account
		// for the height of the call to morestack.
		addEdge(sc.callSize, sc.morestack)
		return maxHeight, edges
	}

	// This function is nosplit, so it adjusts SP without a split
	// check.
	//
	// Walk through SP adjustments in function, consuming relocs
	// and following calls.
	maxLocalHeight := 0
	relocs, ri := ldr.Relocs(sym), 0
	pcsp := obj.NewPCIter(uint32(ctxt.Arch.MinLC))
	for pcsp.Init(ldr.Data(ldr.Pcsp(sym))); !pcsp.Done; pcsp.Next() {
		// pcsp.value is in effect for [pcsp.pc, pcsp.nextpc).
		height := int(pcsp.Value)
		if height > maxLocalHeight {
			maxLocalHeight = height
		}

		// Process calls in this span.
		for ; ri < relocs.Count(); ri++ {
			r := relocs.At(ri)
			if uint32(r.Off()) >= pcsp.NextPC {
				break
			}
			t := r.Type()
			if t.IsDirectCall() || t == objabi.R_CALLIND {
				growth := height + sc.callSize
				var target loader.Sym
				if t == objabi.R_CALLIND {
					target = stackCheckIndirect
				} else {
					target = r.Sym()
				}
				addEdge(growth, target)
			}
		}
	}
	if maxLocalHeight > maxHeight {
		// This is either a leaf function, or the function
		// grew its stack to larger than the maximum call
		// height between calls. Either way, record that local
		// stack growth.
		addEdge(maxLocalHeight, 0)
	}

	return maxHeight, edges
}

func (sc *stackCheck) findRoots() []loader.Sym {
	// Collect all nodes.
	nodes := make(map[loader.Sym]struct{})
	for k := range sc.graph {
		nodes[k] = struct{}{}
	}

	// Start a DFS from each node and delete all reachable
	// children. If we encounter an unrooted cycle, this will
	// delete everything in that cycle, so we detect this case and
	// track the lowest-numbered node encountered in the cycle and
	// put that node back as a root.
	var walk func(origin, sym loader.Sym) (cycle bool, lowest loader.Sym)
	walk = func(origin, sym loader.Sym) (cycle bool, lowest loader.Sym) {
		if _, ok := nodes[sym]; !ok {
			// We already deleted this node.
			return false, 0
		}
		delete(nodes, sym)

		if origin == sym {
			// We found an unrooted cycle. We already
			// deleted all children of this node. Walk
			// back up, tracking the lowest numbered
			// symbol in this cycle.
			return true, sym
		}

		// Delete children of this node.
		for _, out := range sc.graph[sym] {
			if c, l := walk(origin, out.target); c {
				cycle = true
				if lowest == 0 {
					// On first cycle detection,
					// add sym to the set of
					// lowest-numbered candidates.
					lowest = sym
				}
				if l < lowest {
					lowest = l
				}
			}
		}
		return
	}
	for k := range nodes {
		// Delete all children of k.
		for _, out := range sc.graph[k] {
			if cycle, lowest := walk(k, out.target); cycle {
				// This is an unrooted cycle so we
				// just deleted everything. Put back
				// the lowest-numbered symbol.
				nodes[lowest] = struct{}{}
			}
		}
	}

	// Sort roots by height. This makes the result deterministic
	// and also improves the error reporting.
	var roots []loader.Sym
	for k := range nodes {
		roots = append(roots, k)
	}
	sort.Slice(roots, func(i, j int) bool {
		h1, h2 := sc.height[roots[i]], sc.height[roots[j]]
		if h1 != h2 {
			return h1 > h2
		}
		// Secondary sort by Sym.
		return roots[i] < roots[j]
	})
	return roots
}

type stackCheckChain struct {
	stackCheckEdge
	printed bool
}

func (sc *stackCheck) report(sym loader.Sym, depth int, chain *[]stackCheckChain) {
	// Walk the out-edges of sym. We temporarily pull the edges
	// out of the graph to detect cycles and prevent infinite
	// recursion.
	edges, ok := sc.graph[sym]
	isCycle := !(ok || sym == 0)
	delete(sc.graph, sym)
	for _, out := range edges {
		*chain = append(*chain, stackCheckChain{out, false})
		sc.report(out.target, depth-out.growth, chain)
		*chain = (*chain)[:len(*chain)-1]
	}
	sc.graph[sym] = edges

	// If we've reached the end of a chain and it went over the
	// stack limit or was a cycle that would eventually go over,
	// print the whole chain.
	//
	// We should either be in morestack (which has no out-edges)
	// or the sentinel 0 Sym "called" from a leaf function (which
	// has no out-edges), or we came back around a cycle (possibly
	// to ourselves) and edges was temporarily nil'd.
	if len(edges) == 0 && (depth < 0 || isCycle) {
		var indent string
		for i := range *chain {
			ent := &(*chain)[i]
			if ent.printed {
				// Already printed on an earlier part
				// of this call tree.
				continue
			}
			ent.printed = true

			if i == 0 {
				// chain[0] is just the root function,
				// not a stack growth.
				fmt.Printf("%s\n", sc.symName(ent.target))
				continue
			}

			indent = strings.Repeat("    ", i)
			fmt.Print(indent)
			// Grows the stack X bytes and (maybe) calls Y.
			fmt.Printf("grows %d bytes", ent.growth)
			if ent.target == 0 {
				// Not a call, just a leaf. Print nothing.
			} else {
				fmt.Printf(", calls %s", sc.symName(ent.target))
			}
			fmt.Printf("\n")
		}
		// Print how far over this chain went.
		if isCycle {
			fmt.Printf("%sinfinite cycle\n", indent)
		} else {
			fmt.Printf("%s%d bytes over limit\n", indent, -depth)
		}
	}
}
```