Response: Let's break down the thought process for analyzing the `pcln.go` code.

**1. Initial Understanding - The File Name and Package:**

The file path `go/src/cmd/internal/obj/pcln.go` immediately tells us a few things:

* **`go/src`:** This is part of the Go standard library source code.
* **`cmd/internal`:** This indicates an internal package, meant for use within the Go toolchain and not for general import.
* **`obj`:** This suggests it's related to object file generation or manipulation, likely within the compiler or linker.
* **`pcln.go`:**  The `pcln` strongly hints at "PC-Line" information. "PC" likely refers to Program Counter, and "Line" refers to source code line numbers. This suggests the file deals with mapping instructions to their source code locations.

**2. Examining Imports:**

The imports confirm the initial understanding and provide more context:

* **`cmd/internal/goobj`:** Deals with Go object file format.
* **`cmd/internal/objabi`:** Defines object file ABI (Application Binary Interface) constants and types.
* **`encoding/binary`:**  Used for reading and writing binary data, especially variable-length integers, crucial for compact storage of PC-line information.
* **`fmt`:** For formatted output (like debugging prints).
* **`log`:** For logging errors and other information.

**3. Core Function Analysis - `funcpctab`:**

This function appears central. The comment is very informative: "writes to dst a pc-value table mapping the code in func to the values returned by valfunc...". Key takeaways:

* **Purpose:** Creates a mapping between program counter values (locations in the compiled code) and some other value.
* **`valfunc`:**  A function passed as an argument. This function is responsible for determining the "value" associated with each program counter. The parameters of `valfunc` (function, program counter, phase, argument) provide flexibility in how this value is computed.
* **Delta Encoding:** The comment mentions "(value, pc) pairs" and "delta-encoded". This is a common optimization for storing sequences of values that change relatively slowly. Storing only the *differences* saves space. The use of variable-length integers (`binary.PutVarint`, `binary.PutUvarint`) reinforces this.
* **`arg interface{}`:**  Allows passing arbitrary data to `valfunc`.

**4. Analyzing Other Functions - Identifying Specific "Values":**

Now, look at the other functions and see how they are used as `valfunc` arguments to `funcpctab`. This will reveal the *types* of PC-value tables being generated:

* **`pctofileline`:**  Computes either file or line number. When `arg == nil`, it returns the line number. When `arg` is a `*Pcln`, it returns the file index and updates `pcln.UsedFiles`. This confirms that one PC-value table maps PCs to file numbers, and another maps PCs to line numbers.
* **`pctospadj`:** Computes stack pointer adjustments. The "value" here is the change in the stack pointer at a given PC.
* **`pctoinline`:** Deals with inlining information. The "value" is an index into an inlining tree.
* **`pctopcdata`:** Handles `PCDATA` instructions, which store auxiliary data associated with code points. The "value" is the data set by the `PCDATA` instruction.

**5. The `pcinlineState` Structure:**

This structure is specifically for managing the inlining tree. The `addBranch` method builds a local representation of the inlining tree based on a global tree.

**6. The `linkpcln` Function:**

This function orchestrates the creation of all the PC-value tables for a given function (`cursym`). It iterates through the instructions and uses `funcpctab` with the different `valfunc` implementations to generate the `Pcsp`, `Pcfile`, `Pcline`, and `Pcinline` tables. It also handles `FUNCDATA`.

**7. The `PCIter` Structure:**

This is a helper struct for *iterating* over the delta-encoded PC-value tables. The `Next()` method decodes the next (value, pc) pair.

**8. Inferring the Go Feature:**

Based on the identified PC-value tables, the function names, and the overall structure, the core Go feature being implemented is **runtime reflection and debugging information**. Specifically, the information generated here is used for:

* **Stack Traces:** Mapping program counters back to source code lines and file names.
* **Debugging Tools (like `gdb` or `dlv`):** Allowing breakpoints and stepping through code at the source level.
* **Panic Handling:** Providing context about where a panic occurred.
* **Profiling:** Relating performance data back to specific lines of code.
* **Inlining Information:**  Understanding how functions were inlined, which is crucial for debugging optimized code.

**9. Code Example and Assumptions:**

To create a code example, focus on a simple case like mapping PCs to line numbers. Assume a basic function and trace how `pctofileline` and `funcpctab` would work. This requires making educated guesses about the instruction sequence (which is architecture-dependent and not fully visible in this snippet).

**10. Command-Line Arguments and Error Prone Areas:**

The `ctxt.Debugpcln` variable suggests a command-line flag for debugging PC-line generation. The `linkpcln` function's logic for handling `PCDATA` and `FUNCDATA` hints at potential errors if these directives are used incorrectly.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe it's just about stack traces.
* **Correction:** The presence of inlining information (`pctoinline`, `pcinlineState`) broadens the scope to debugging optimized code.
* **Initial thought:**  Focus heavily on the binary encoding details.
* **Refinement:**  While important, the *purpose* of the encoding (efficient storage of PC-value mappings) is more crucial for understanding the overall functionality.

By following this structured approach of examining the file path, imports, function signatures, comments, and then connecting the pieces, we can arrive at a comprehensive understanding of the `pcln.go` code and the Go features it implements.
这段代码是 Go 语言编译器（`cmd/compile`）中用于生成 **PC-value 表** (PC-value tables) 的一部分。PC-value 表是 Go 运行时 (runtime) 用于实现诸如栈回溯、调试信息、以及 `recover` 等功能的重要数据结构。

**功能概述:**

这段代码的核心功能是生成和管理与程序计数器 (PC) 相关联的值的表格。这些表格记录了在代码执行的不同位置（由 PC 值标识）生效的各种信息。  具体来说，它负责以下几个关键任务：

1. **`funcpctab` 函数：** 这是生成 PC-value 表的核心函数。它接收一个函数 ( `func_` )，一个描述 ( `desc` )，一个用于计算与 PC 关联值的函数 ( `valfunc` )，以及一个传递给 `valfunc` 的参数 ( `arg` )。它遍历函数中的指令，并调用 `valfunc` 来获取在每个指令位置的值，并将这些值和对应的 PC 值编码到一个字节数组中。

2. **各种 `valfunc` 函数：**  代码中定义了多个不同的 `valfunc` 函数，每个函数负责计算特定类型的值：
   - **`pctofileline`:**  计算给定 PC 对应的源文件名和行号。
   - **`pctoinline`:**  计算给定 PC 处是否发生了函数内联，并返回内联树中的索引。
   - **`pctospadj`:**  计算给定 PC 处的栈指针调整量 (stack pointer adjustment)。
   - **`pctopcdata`:**  计算给定 PC 处生效的 PCDATA 指令的值。

3. **`linkpcln` 函数：**  这个函数是连接和组织所有 PC-value 表的入口点。它遍历函数中的指令，识别 `PCDATA` 和 `FUNCDATA` 指令，并为不同的 PC-value 类型调用 `funcpctab` 生成相应的表格。它还会处理内联信息的关联。

4. **`PCIter` 结构体：**  这是一个用于迭代解码 PC-value 表的结构体。它提供了一种按顺序访问 PC 和对应值的方法。

**实现的 Go 语言功能:**

这段代码是 Go 语言运行时实现以下功能的基础：

* **栈回溯 (Stack Traces):**  `pctofileline` 生成的表格使得运行时能够根据程序崩溃时的 PC 值，找到对应的源文件名和行号，从而生成易于理解的错误报告。
* **`recover` 函数:**  `recover` 函数需要知道当前执行的上下文，包括函数调用栈。PC-value 表中的信息用于在 `panic` 发生时，向上遍历调用栈，找到可以执行 `recover` 的帧。
* **调试信息 (DWARF):**  编译器生成的 PC-value 表可以被转换成 DWARF 调试信息，供调试器（如 `gdb` 或 `dlv`）使用，实现断点、单步调试等功能。
* **性能分析 (Profiling):**  性能分析工具可以利用 PC-value 表将性能数据（如 CPU 占用时间）映射回源代码行，帮助开发者定位性能瓶颈。
* **函数内联 (Function Inlining):**  `pctoinline` 生成的表格记录了函数内联的信息，使得调试器和性能分析工具能够理解经过内联优化的代码。
* **Goroutine 栈管理:** `pctospadj` 记录的栈指针调整量对于理解和管理 goroutine 的栈至关重要。
* **`PCDATA` 和 `FUNCDATA` 指令:** 这两个指令允许在编译时向 PC-value 表中添加额外的元数据，这些数据可以被运行时或调试器使用。

**Go 代码示例:**

以下是一个简单的 Go 代码示例，并假设编译器在编译时会使用 `pcln.go` 中的逻辑来生成 PC-value 表：

```go
package main

import "fmt"

func add(a, b int) int {
	return a + b
}

func main() {
	x := 10
	y := 20
	sum := add(x, y) // 假设编译器会记录这里到 add 函数的调用
	fmt.Println(sum)
}
```

**代码推理（假设）：**

**假设输入：** 上述 `main.go` 文件的抽象语法树（AST）表示，以及目标架构的信息。

**`funcpctab` 调用示例 (针对 `pctofileline`)：**

编译器在处理 `add` 函数时，可能会调用 `funcpctab`，并将 `pctofileline` 作为 `valfunc` 传入。

```go
// 假设在 cmd/compile/internal/gc 包中
// ...
import "cmd/internal/obj"
// ...

func compileFunc(ctxt *obj.Link, fn *Node) {
	// ...
	pcln := &fn.Func.Pcln // 获取函数的 Pcln 结构体
	pcln.Pcfile = obj.Funcpctab(ctxt, fn.Sym, "pctofile", obj.Pctofileline, pcln)
	// ...
}
```

**假设 `pctofileline` 的调用过程和输出：**

假设 `add` 函数编译后的指令如下（简化）：

| PC   | 指令      | 源文件行号 |
|------|-----------|----------|
| 0x10 | MOV a, R1 | 5        | // return a + b
| 0x14 | MOV b, R2 | 5        |
| 0x18 | ADD R1, R2 | 5        |
| 0x1C | RET       | 5        |

当 `funcpctab` 调用 `pctofileline` 时，对于 `add` 函数的每个指令 `p`：

- `pctofileline(ctxt, add_LSym, oldval, p, 0, pcln)` 会返回当前指令所在文件的索引。假设 `main.go` 文件的索引是 0。
- `pctofileline(ctxt, add_LSym, oldval, p, 1, pcln)` 不会改变 `oldval`。

`funcpctab` 会将这些信息编码成一个字节数组，例如：

```
[0x00,  // 文件索引 0
 0x04,  // PC 偏移量 (0x14 - 0x10) / MinLC
 0x00,  // 文件索引 0 (没有变化)
 0x04,  // PC 偏移量 (0x18 - 0x14) / MinLC
 0x00,  // 文件索引 0 (没有变化)
 0x04,  // PC 偏移量 (0x1C - 0x18) / MinLC
 0x00,  // 文件索引 0 (没有变化)
 0x00   // 终止符
]
```

**命令行参数的具体处理:**

代码中出现了 `ctxt.Debugpcln`，这暗示了可能存在一个命令行参数用于控制 `pcln` 相关的调试输出。这个参数很可能是在 Go 编译器的命令行中通过 `-gcflags` 传递的，例如：

```bash
go build -gcflags="-d=pcln=pctofile" main.go
```

这个命令会指示编译器在生成 `pctofile` 表格时输出详细的调试信息。具体的参数解析和处理逻辑通常在 `cmd/compile/internal/gc` 包或其他编译器相关的包中。

**使用者易犯错的点:**

作为 `cmd/internal` 下的包，`obj` 包及其子包通常不直接被最终用户使用。  开发者不太可能直接与 `pcln.go` 中的函数交互。

然而，**对于 Go 语言工具链的开发者**，理解 `pcln.go` 的工作原理至关重要，因为：

1. **错误的 `PCDATA` 或 `FUNCDATA` 指令:**  如果在汇编代码中使用了错误的 `PCDATA` 或 `FUNCDATA` 指令，可能会导致生成的 PC-value 表不正确，从而影响栈回溯、调试等功能。例如，定义了超出范围的 `PCDATA` 索引。

   ```assembly
   TEXT ·myFunc(SB),$0-0
       // 错误示例：定义了超出预期的 PCDATA 索引
       PCDATA $100, $1
       RET
   ```

2. **不正确的内联信息:**  如果编译器在生成内联信息时出现错误，`pctoinline` 生成的表格可能不准确，导致调试器无法正确展示内联的函数调用栈。

3. **修改编译器代码:**  任何对编译器生成 PC-value 表相关代码的修改都可能引入错误，导致运行时行为异常或调试信息不正确。

**总结:**

`go/src/cmd/internal/obj/pcln.go` 是 Go 语言工具链中一个非常核心的组件，它负责生成用于支持运行时反射、调试和错误处理的关键数据结构。虽然普通 Go 开发者不会直接使用它，但理解其功能有助于深入理解 Go 语言的底层实现机制。对于 Go 工具链的开发者来说，正确理解和维护这段代码至关重要。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/pcln.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package obj

import (
	"cmd/internal/goobj"
	"cmd/internal/objabi"
	"encoding/binary"
	"fmt"
	"log"
)

// funcpctab writes to dst a pc-value table mapping the code in func to the values
// returned by valfunc parameterized by arg. The invocation of valfunc to update the
// current value is, for each p,
//
//	sym = valfunc(func, p, 0, arg);
//	record sym.P as value at p->pc;
//	sym = valfunc(func, p, 1, arg);
//
// where func is the function, val is the current value, p is the instruction being
// considered, and arg can be used to further parameterize valfunc.
func funcpctab(ctxt *Link, func_ *LSym, desc string, valfunc func(*Link, *LSym, int32, *Prog, int32, interface{}) int32, arg interface{}) *LSym {
	dbg := desc == ctxt.Debugpcln
	dst := []byte{}
	sym := &LSym{
		Type:      objabi.SRODATA,
		Attribute: AttrContentAddressable | AttrPcdata,
	}

	if dbg {
		ctxt.Logf("funcpctab %s [valfunc=%s]\n", func_.Name, desc)
	}

	val := int32(-1)
	oldval := val
	fn := func_.Func()
	if fn.Text == nil {
		// Return the empty symbol we've built so far.
		return sym
	}

	pc := fn.Text.Pc

	if dbg {
		ctxt.Logf("%6x %6d %v\n", uint64(pc), val, fn.Text)
	}

	buf := make([]byte, binary.MaxVarintLen32)
	started := false
	for p := fn.Text; p != nil; p = p.Link {
		// Update val. If it's not changing, keep going.
		val = valfunc(ctxt, func_, val, p, 0, arg)

		if val == oldval && started {
			val = valfunc(ctxt, func_, val, p, 1, arg)
			if dbg {
				ctxt.Logf("%6x %6s %v\n", uint64(p.Pc), "", p)
			}
			continue
		}

		// If the pc of the next instruction is the same as the
		// pc of this instruction, this instruction is not a real
		// instruction. Keep going, so that we only emit a delta
		// for a true instruction boundary in the program.
		if p.Link != nil && p.Link.Pc == p.Pc {
			val = valfunc(ctxt, func_, val, p, 1, arg)
			if dbg {
				ctxt.Logf("%6x %6s %v\n", uint64(p.Pc), "", p)
			}
			continue
		}

		// The table is a sequence of (value, pc) pairs, where each
		// pair states that the given value is in effect from the current position
		// up to the given pc, which becomes the new current position.
		// To generate the table as we scan over the program instructions,
		// we emit a "(value" when pc == func->value, and then
		// each time we observe a change in value we emit ", pc) (value".
		// When the scan is over, we emit the closing ", pc)".
		//
		// The table is delta-encoded. The value deltas are signed and
		// transmitted in zig-zag form, where a complement bit is placed in bit 0,
		// and the pc deltas are unsigned. Both kinds of deltas are sent
		// as variable-length little-endian base-128 integers,
		// where the 0x80 bit indicates that the integer continues.

		if dbg {
			ctxt.Logf("%6x %6d %v\n", uint64(p.Pc), val, p)
		}

		if started {
			pcdelta := (p.Pc - pc) / int64(ctxt.Arch.MinLC)
			n := binary.PutUvarint(buf, uint64(pcdelta))
			dst = append(dst, buf[:n]...)
			pc = p.Pc
		}

		delta := val - oldval
		n := binary.PutVarint(buf, int64(delta))
		dst = append(dst, buf[:n]...)
		oldval = val
		started = true
		val = valfunc(ctxt, func_, val, p, 1, arg)
	}

	if started {
		if dbg {
			ctxt.Logf("%6x done\n", uint64(fn.Text.Pc+func_.Size))
		}
		v := (func_.Size - pc) / int64(ctxt.Arch.MinLC)
		if v < 0 {
			ctxt.Diag("negative pc offset: %v", v)
		}
		n := binary.PutUvarint(buf, uint64(v))
		dst = append(dst, buf[:n]...)
		// add terminating varint-encoded 0, which is just 0
		dst = append(dst, 0)
	}

	if dbg {
		ctxt.Logf("wrote %d bytes to %p\n", len(dst), dst)
		for _, p := range dst {
			ctxt.Logf(" %02x", p)
		}
		ctxt.Logf("\n")
	}

	sym.Size = int64(len(dst))
	sym.P = dst
	return sym
}

// pctofileline computes either the file number (arg == 0)
// or the line number (arg == 1) to use at p.
// Because p.Pos applies to p, phase == 0 (before p)
// takes care of the update.
func pctofileline(ctxt *Link, sym *LSym, oldval int32, p *Prog, phase int32, arg interface{}) int32 {
	if p.As == ATEXT || p.As == ANOP || p.Pos.Line() == 0 || phase == 1 {
		return oldval
	}
	f, l := ctxt.getFileIndexAndLine(p.Pos)
	if arg == nil {
		return l
	}
	pcln := arg.(*Pcln)
	pcln.UsedFiles[goobj.CUFileIndex(f)] = struct{}{}
	return int32(f)
}

// pcinlineState holds the state used to create a function's inlining
// tree and the PC-value table that maps PCs to nodes in that tree.
type pcinlineState struct {
	globalToLocal map[int]int
	localTree     InlTree
}

// addBranch adds a branch from the global inlining tree in ctxt to
// the function's local inlining tree, returning the index in the local tree.
func (s *pcinlineState) addBranch(ctxt *Link, globalIndex int) int {
	if globalIndex < 0 {
		return -1
	}

	localIndex, ok := s.globalToLocal[globalIndex]
	if ok {
		return localIndex
	}

	// Since tracebacks don't include column information, we could
	// use one node for multiple calls of the same function on the
	// same line (e.g., f(x) + f(y)). For now, we use one node for
	// each inlined call.
	call := ctxt.InlTree.nodes[globalIndex]
	call.Parent = s.addBranch(ctxt, call.Parent)
	localIndex = len(s.localTree.nodes)
	s.localTree.nodes = append(s.localTree.nodes, call)
	s.globalToLocal[globalIndex] = localIndex
	return localIndex
}

func (s *pcinlineState) setParentPC(ctxt *Link, globalIndex int, pc int32) {
	localIndex, ok := s.globalToLocal[globalIndex]
	if !ok {
		// We know where to unwind to when we need to unwind a body identified
		// by globalIndex. But there may be no instructions generated by that
		// body (it's empty, or its instructions were CSEd with other things, etc.).
		// In that case, we don't need an unwind entry.
		// TODO: is this really right? Seems to happen a whole lot...
		return
	}
	s.localTree.setParentPC(localIndex, pc)
}

// pctoinline computes the index into the local inlining tree to use at p.
// If p is not the result of inlining, pctoinline returns -1. Because p.Pos
// applies to p, phase == 0 (before p) takes care of the update.
func (s *pcinlineState) pctoinline(ctxt *Link, sym *LSym, oldval int32, p *Prog, phase int32, arg interface{}) int32 {
	if phase == 1 {
		return oldval
	}

	posBase := ctxt.PosTable.Pos(p.Pos).Base()
	if posBase == nil {
		return -1
	}

	globalIndex := posBase.InliningIndex()
	if globalIndex < 0 {
		return -1
	}

	if s.globalToLocal == nil {
		s.globalToLocal = make(map[int]int)
	}

	return int32(s.addBranch(ctxt, globalIndex))
}

// pctospadj computes the sp adjustment in effect.
// It is oldval plus any adjustment made by p itself.
// The adjustment by p takes effect only after p, so we
// apply the change during phase == 1.
func pctospadj(ctxt *Link, sym *LSym, oldval int32, p *Prog, phase int32, arg interface{}) int32 {
	if oldval == -1 { // starting
		oldval = 0
	}
	if phase == 0 {
		return oldval
	}
	if oldval+p.Spadj < -10000 || oldval+p.Spadj > 1100000000 {
		ctxt.Diag("overflow in spadj: %d + %d = %d", oldval, p.Spadj, oldval+p.Spadj)
		ctxt.DiagFlush()
		log.Fatalf("bad code")
	}

	return oldval + p.Spadj
}

// pctopcdata computes the pcdata value in effect at p.
// A PCDATA instruction sets the value in effect at future
// non-PCDATA instructions.
// Since PCDATA instructions have no width in the final code,
// it does not matter which phase we use for the update.
func pctopcdata(ctxt *Link, sym *LSym, oldval int32, p *Prog, phase int32, arg interface{}) int32 {
	if phase == 0 || p.As != APCDATA || p.From.Offset != int64(arg.(uint32)) {
		return oldval
	}
	if int64(int32(p.To.Offset)) != p.To.Offset {
		ctxt.Diag("overflow in PCDATA instruction: %v", p)
		ctxt.DiagFlush()
		log.Fatalf("bad code")
	}

	return int32(p.To.Offset)
}

func linkpcln(ctxt *Link, cursym *LSym) {
	pcln := &cursym.Func().Pcln
	pcln.UsedFiles = make(map[goobj.CUFileIndex]struct{})

	npcdata := 0
	nfuncdata := 0
	for p := cursym.Func().Text; p != nil; p = p.Link {
		// Find the highest ID of any used PCDATA table. This ignores PCDATA table
		// that consist entirely of "-1", since that's the assumed default value.
		//   From.Offset is table ID
		//   To.Offset is data
		if p.As == APCDATA && p.From.Offset >= int64(npcdata) && p.To.Offset != -1 { // ignore -1 as we start at -1, if we only see -1, nothing changed
			npcdata = int(p.From.Offset + 1)
		}
		// Find the highest ID of any FUNCDATA table.
		//   From.Offset is table ID
		if p.As == AFUNCDATA && p.From.Offset >= int64(nfuncdata) {
			nfuncdata = int(p.From.Offset + 1)
		}
	}

	pcln.Pcdata = make([]*LSym, npcdata)
	pcln.Funcdata = make([]*LSym, nfuncdata)

	pcln.Pcsp = funcpctab(ctxt, cursym, "pctospadj", pctospadj, nil)
	pcln.Pcfile = funcpctab(ctxt, cursym, "pctofile", pctofileline, pcln)
	pcln.Pcline = funcpctab(ctxt, cursym, "pctoline", pctofileline, nil)

	// Check that all the Progs used as inline markers are still reachable.
	// See issue #40473.
	fn := cursym.Func()
	inlMarkProgs := make(map[*Prog]struct{}, len(fn.InlMarks))
	for _, inlMark := range fn.InlMarks {
		inlMarkProgs[inlMark.p] = struct{}{}
	}
	for p := fn.Text; p != nil; p = p.Link {
		delete(inlMarkProgs, p)
	}
	if len(inlMarkProgs) > 0 {
		ctxt.Diag("one or more instructions used as inline markers are no longer reachable")
	}

	pcinlineState := new(pcinlineState)
	pcln.Pcinline = funcpctab(ctxt, cursym, "pctoinline", pcinlineState.pctoinline, nil)
	for _, inlMark := range fn.InlMarks {
		pcinlineState.setParentPC(ctxt, int(inlMark.id), int32(inlMark.p.Pc))
	}
	pcln.InlTree = pcinlineState.localTree
	if ctxt.Debugpcln == "pctoinline" && len(pcln.InlTree.nodes) > 0 {
		ctxt.Logf("-- inlining tree for %s:\n", cursym)
		dumpInlTree(ctxt, pcln.InlTree)
		ctxt.Logf("--\n")
	}

	// tabulate which pc and func data we have.
	havepc := make([]uint32, (npcdata+31)/32)
	havefunc := make([]uint32, (nfuncdata+31)/32)
	for p := fn.Text; p != nil; p = p.Link {
		if p.As == AFUNCDATA {
			if (havefunc[p.From.Offset/32]>>uint64(p.From.Offset%32))&1 != 0 {
				ctxt.Diag("multiple definitions for FUNCDATA $%d", p.From.Offset)
			}
			havefunc[p.From.Offset/32] |= 1 << uint64(p.From.Offset%32)
		}

		if p.As == APCDATA && p.To.Offset != -1 {
			havepc[p.From.Offset/32] |= 1 << uint64(p.From.Offset%32)
		}
	}

	// pcdata.
	for i := 0; i < npcdata; i++ {
		if (havepc[i/32]>>uint(i%32))&1 == 0 {
			// use an empty symbol.
			pcln.Pcdata[i] = &LSym{
				Type:      objabi.SRODATA,
				Attribute: AttrContentAddressable | AttrPcdata,
			}
		} else {
			pcln.Pcdata[i] = funcpctab(ctxt, cursym, "pctopcdata", pctopcdata, interface{}(uint32(i)))
		}
	}

	// funcdata
	if nfuncdata > 0 {
		for p := fn.Text; p != nil; p = p.Link {
			if p.As != AFUNCDATA {
				continue
			}
			i := int(p.From.Offset)
			if p.To.Type != TYPE_MEM || p.To.Offset != 0 {
				panic(fmt.Sprintf("bad funcdata: %v", p))
			}
			pcln.Funcdata[i] = p.To.Sym
		}
	}
}

// PCIter iterates over encoded pcdata tables.
type PCIter struct {
	p       []byte
	PC      uint32
	NextPC  uint32
	PCScale uint32
	Value   int32
	start   bool
	Done    bool
}

// NewPCIter creates a PCIter with a scale factor for the PC step size.
func NewPCIter(pcScale uint32) *PCIter {
	it := new(PCIter)
	it.PCScale = pcScale
	return it
}

// Next advances it to the Next pc.
func (it *PCIter) Next() {
	it.PC = it.NextPC
	if it.Done {
		return
	}
	if len(it.p) == 0 {
		it.Done = true
		return
	}

	// Value delta
	val, n := binary.Varint(it.p)
	if n <= 0 {
		log.Fatalf("bad Value varint in pciterNext: read %v", n)
	}
	it.p = it.p[n:]

	if val == 0 && !it.start {
		it.Done = true
		return
	}

	it.start = false
	it.Value += int32(val)

	// pc delta
	pc, n := binary.Uvarint(it.p)
	if n <= 0 {
		log.Fatalf("bad pc varint in pciterNext: read %v", n)
	}
	it.p = it.p[n:]

	it.NextPC = it.PC + uint32(pc)*it.PCScale
}

// init prepares it to iterate over p,
// and advances it to the first pc.
func (it *PCIter) Init(p []byte) {
	it.p = p
	it.PC = 0
	it.NextPC = 0
	it.Value = -1
	it.start = true
	it.Done = false
	it.Next()
}

"""



```