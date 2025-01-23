Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The primary goal is to analyze a segment of Go code from `go/src/cmd/compile/internal/ssagen/ssa.go` and describe its functionality, related Go features, usage, and potential pitfalls. The fact that this is part 6 of 8 suggests a larger context of generating Static Single Assignment (SSA) form.

2. **Initial Scan and Keyword Spotting:**  Quickly read through the code, looking for keywords and recognizable patterns. Terms like `ir.ONAME`, `ssa.CanSSA`, `exprPtr`, `nilCheck`, `boundsCheck`, `rtcall`, `storeType`, `slice`, `dottype`, and function names like `uint64Tofloat64` jump out. These hint at different functionalities within the SSA generation process.

3. **Group Functions by Purpose:** Start grouping related functions. For instance:
    * `canSSAName` and the anonymous function at the beginning seem related to determining if a variable can be represented in SSA form.
    * `exprPtr` and `nilCheck` clearly deal with pointer dereferencing and nil checks.
    * `boundsCheck` is explicitly for array/slice bounds checking.
    * `rtcall` implies calling runtime functions.
    * The `storeType` family deals with memory stores and potentially write barriers.
    * `slice` handles slice operations.
    * The `uint64Tofloat*` and `float*ToUint*` families are about type conversions.
    * `referenceTypeBuiltin` handles `len` and `cap` for maps and channels.
    * `dottype` and `dynamicDottype` are for type assertions.

4. **Analyze Individual Function Logic:**  For each group, examine the functions in more detail.
    * **SSA-ability:** `canSSAName` checks conditions like `Addrtaken`, `OnStack`, and `Class` to decide if a variable is suitable for SSA representation. The return value handling in deferred functions and `cgoUnsafeArgs` are interesting edge cases.
    * **Pointer and Nil Checks:** `exprPtr` wraps `expr` and adds a nil check if necessary. `nilCheck` itself generates the `ssa.OpNilCheck` instruction.
    * **Bounds Checking:**  `boundsCheck` is complex. It extends the index, handles `bounded` cases (compiler-generated indices), and emits `ssa.OpIsInBounds` or `ssa.OpIsSliceInBounds` followed by conditional branching to a panic block. The Spectre mitigation is also noteworthy.
    * **Runtime Calls:** `rtcall` is about generating calls to runtime functions. It handles argument passing and result retrieval.
    * **Memory Stores:** The `storeType` family deals with storing values in memory, paying attention to pointer types and potential write barriers (though the implementation details of the write barrier aren't fully present in this snippet).
    * **Slicing:** `slice` handles the logic of creating new slices, including bounds checking and pointer arithmetic.
    * **Type Conversions:** The `uint64Tofloat*` and `float*ToUint*` functions demonstrate how the compiler handles specific conversions between unsigned integers and floating-point numbers, often with conditional logic to manage potential precision issues or representation differences.
    * **`len`/`cap` for Maps/Channels:** `referenceTypeBuiltin` shows the inlining logic for `len` and `cap` on maps and channels, including handling nil cases.
    * **Type Assertions:** `dottype` and `dynamicDottype` implement type assertions, potentially involving runtime calls and checks for nil interfaces. The code mentions optimizations involving a type assertion cache.

5. **Infer Go Feature Implementations:** Connect the analyzed functions to corresponding Go language features:
    * SSA-ability: Relates to compiler optimizations and how variables are tracked.
    * Pointer/Nil checks: Directly relates to Go's nil pointer safety and runtime checks.
    * Bounds checks: Implements Go's array/slice bounds safety.
    * Runtime calls: Shows how built-in functions or operations requiring runtime support are handled (e.g., `panicdivide`, memory allocation).
    * Memory stores/Write barriers:  Underpins assignment operations, especially for types containing pointers, to ensure memory safety in the presence of garbage collection.
    * Slicing:  Implements Go's slice syntax.
    * Type conversions: Handles explicit type conversions in Go.
    * `len`/`cap`: Implements these built-in functions for maps and channels.
    * Type assertions: Implements Go's type assertion syntax (`x.(T)` and `x, ok := y.(T)`).

6. **Construct Examples and Scenarios:** Think about how these functions would be used in concrete Go code. This helps illustrate the functionality and potential pitfalls. Examples for nil checks, bounds checks, slicing, type conversions, and type assertions are relevant.

7. **Consider Command-Line Arguments and Error Prone Areas:**  Look for mentions of flags (like `base.Flag.B` for disabling bounds checks or `base.Flag.Cfg.SpectreIndex`) which indicate command-line influence. Identify situations where developers might make mistakes (e.g., relying on implicit nil checks that might be removed, incorrect slice indices, misunderstandings about type assertions).

8. **Synthesize a Summary:**  Combine the findings into a concise summary of the code's overall function within the SSA generation process. Emphasize the key areas covered.

9. **Structure the Answer:** Organize the information logically with clear headings and examples to make it easy to understand. Use the prompt's requirements (Chinese language, code examples, etc.) as a guide.

**Self-Correction/Refinement during the Process:**

* **Initial Overgeneralization:**  Initially, one might broadly say "this code generates SSA."  The refinement is to pinpoint *what aspects* of Go semantics are being translated into SSA instructions.
* **Missing Nuances:**  On the first pass, I might miss the subtleties of the Spectre mitigation in `boundsCheck` or the different scenarios for type assertions (empty vs. non-empty interfaces). Rereading and focusing on the conditional logic helps uncover these details.
* **Clarity of Examples:** The initial code examples might be too simplistic. Thinking about edge cases and more realistic scenarios improves the examples.
* **Connecting to Go Concepts:**  It's important to explicitly link the code's actions to well-known Go features. For example, don't just say `storeType` stores data; explain that it relates to Go's assignment operator and memory model.

By following this structured approach, combining code analysis with knowledge of Go's features, and refining the analysis along the way, one can arrive at a comprehensive and accurate explanation of the code snippet's functionality.
这是 `go/src/cmd/compile/internal/ssagen/ssa.go` 文件的一部分，主要负责将 Go 语言的中间表示 (IR) 转换为静态单赋值 (SSA) 形式的指令。这是 Go 编译器进行优化的重要步骤。

**第 6 部分的功能归纳：**

这部分代码主要集中在以下几个方面，延续了 SSA 生成过程中的关键任务：

1. **处理内置函数和操作:** 包含了对一些内置函数（如 `len`、`cap`）以及类型转换、类型断言等操作的 SSA 生成逻辑。

2. **实现类型转换:**  详细展示了各种数值类型之间以及浮点数与无符号整数之间的转换的具体 SSA 指令生成过程，考虑了不同数据类型的表示和转换规则。

3. **实现类型断言:**  负责将 Go 语言的类型断言表达式转换为 SSA 指令，包括判断断言是否成功，以及在断言失败时的 panic 处理。

**更具体的功能列表：**

* **`canSSAName(name *ir.Name) bool`:** 判断一个 `ir.Name`（通常代表一个变量名）是否可以被表示为 SSA 值。这涉及到检查变量是否被取地址、是否在栈上以及其类别等信息。对于某些情况（如命名返回值在 `defer` 存在时，或 cgo 的 unsafe 参数），即使变量在栈上也不适合 SSA 化。

* **`exprPtr(n ir.Node, bounded bool, lineno src.XPos) *ssa.Value`:** 将一个 `ir.Node` 求值为一个指针，并根据 `bounded` 参数和节点的 `NonNil()` 属性决定是否插入 nil 检查。

* **`nilCheck(ptr *ssa.Value) *ssa.Value`:** 生成 nil 指针检查的代码。只有在自动插入 nil 检查时使用，而不是用户显式写的 `x != nil`。返回一个“确定非 nil”的指针副本。

* **`boundsCheck(idx, len *ssa.Value, kind ssa.BoundsKind, bounded bool) *ssa.Value`:** 生成边界检查的代码。检查索引 `idx` 是否在 `0` 到 `len` 之间。如果超出范围则跳转到 panic 分支。`bounded` 为 true 时表示调用者保证索引不越界，可以跳过检查（但仍会进行类型扩展）。还包括了针对 Spectre 漏洞的缓解措施 (`SpectreIndex`)。

* **`check(cmp *ssa.Value, fn *obj.LSym)`:** 如果布尔值 `cmp` 为 false，则调用运行时函数 `fn` 进行 panic。

* **`intDivide(n ir.Node, a, b *ssa.Value) *ssa.Value`:** 处理整数除法操作，在除数为常量且非零时可以跳过零值检查，否则会插入检查并可能 panic。

* **`rtcall(fn *obj.LSym, returns bool, results []*types.Type, args ...*ssa.Value)`:** 生成对运行时函数 `fn` 的调用。处理参数传递和返回值接收。如果 `returns` 为 false，则将当前块标记为退出块。

* **`storeType(t *types.Type, left, right *ssa.Value, skip skipMask, leftIsStmt bool)`:** 生成将 `right` 的值存储到 `left` 指向的内存位置的代码。考虑了类型的指针属性，可能需要插入写屏障 (write barrier)。

* **`storeTypeScalars(...)` 和 `storeTypePtrs(...)`:**  `storeType` 的辅助函数，分别处理非指针字段和指针字段的存储，这是为了优化写屏障的性能。

* **`putArg(n ir.Node, t *types.Type) *ssa.Value`:**  为了将 `n` 作为参数传递给函数而对其求值。

* **`storeArgWithBase(n ir.Node, t *types.Type, base *ssa.Value, off int64)`:** 将 `n` 的值存储到相对于 `base` 指针偏移 `off` 的位置。

* **`slice(v, i, j, k *ssa.Value, bounded bool) (p, l, c *ssa.Value)`:**  处理切片操作 `v[i:j:k]`，计算新切片的指针、长度和容量。包含了详细的边界检查逻辑。

* **`uint64Tofloat64(...)`, `uint64Tofloat32(...)`, `uint32Tofloat64(...)`, `uint32Tofloat32(...)` 以及辅助函数 `uint64Tofloat(...)` 和 `uint32Tofloat(...)`:**  实现将无符号 64 位和 32 位整数转换为浮点数的 SSA 生成。由于硬件对大无符号数的转换可能存在精度问题，这里使用了特殊的处理逻辑。

* **`referenceTypeBuiltin(n *ir.UnaryExpr, x *ssa.Value) *ssa.Value`:** 处理针对 map 和 channel 类型的内置函数 `len` 和 `cap`。

* **`float32ToUint64(...)`, `float64ToUint64(...)`, `float32ToUint32(...)`, `float64ToUint32(...)` 以及辅助函数 `floatToUint(...)`:** 实现将浮点数转换为无符号整数的 SSA 生成，同样需要处理精度问题。

* **`dottype(n *ir.TypeAssertExpr, commaok bool) (res, resok *ssa.Value)` 和 `dynamicDottype(n *ir.DynamicTypeAssertExpr, commaok bool) (res, resok *ssa.Value)` 以及核心函数 `dottype1(...)`:**  实现类型断言的 SSA 生成。`commaok` 参数决定了断言失败时是 panic 还是返回一个布尔值。包含了对空接口和非空接口的转换处理，以及对运行时函数 `panicnildottype` 的调用。还可能涉及到类型断言缓存的检查。

**Go 语言功能实现举例：**

**1. 切片操作：**

```go
package main

func main() {
	arr := [5]int{1, 2, 3, 4, 5}
	slice1 := arr[1:4] // 假设输入 i=1, j=4, k=5 (默认)
	println(len(slice1), cap(slice1)) // 输出 3 4

	slice2 := slice1[0:2] // 假设输入 i=0, j=2, k=3 (默认)
	println(len(slice2), cap(slice2)) // 输出 2 3
}
```

**假设的 SSA 生成过程 (针对 `slice1 := arr[1:4]`):**

* **输入 `v` (代表 `arr`) 的 SSA 值， `i` 的 SSA 值 (代表常量 1)， `j` 的 SSA 值 (代表常量 4)， `k` 为 nil。**
* `slice` 函数会被调用。
* 由于 `arr` 是数组，`ptr` 会指向 `arr` 的起始地址， `len` 和 `cap` 都是常量 5。
* 默认值处理后，`i` 为 1， `j` 为 4， `k` 为 5。
* **边界检查:**
    * `j` (4) 与 `k` (5) 比较，生成 SSA 指令检查 `4 <= 5`。
    * `i` (1) 与 `j` (4) 比较，生成 SSA 指令检查 `1 <= 4`。
* **计算新切片的长度和容量:**
    * `rlen = j - i = 4 - 1 = 3`，生成 `ssa.OpSub` 指令。
    * `rcap = k - i = 5 - 1 = 4`，生成 `ssa.OpSub` 指令。
* **计算新切片的起始指针:**
    * `stride` 为 `int` 的大小。
    * `delta = i * stride = 1 * sizeof(int)`，生成 `ssa.OpMul` 指令。
    * `rptr = ptr + delta`，生成 `ssa.OpAddPtr` 指令。
* **`slice` 函数返回 `rptr`， `rlen`， `rcap` 的 SSA 值，用于后续赋值给 `slice1`。**

**2. 类型断言：**

```go
package main

func main() {
	var i interface{} = "hello"

	s, ok := i.(string) // 假设输入 n 指向这个类型断言表达式

	if ok {
		println("断言成功:", s)
	} else {
		println("断言失败")
	}

	// 另一个例子，可能触发 panic
	var j interface{} = 10
	_ = j.(string)
}
```

**假设的 SSA 生成过程 (针对 `s, ok := i.(string)`):**

* **输入 `iface` (代表 `i`) 的 SSA 值，目标类型 `string`。 `commaok` 为 true。**
* `dottype` 函数会被调用。
* `target` 会是 `string` 类型的反射类型信息。
* `dottype1` 函数会被调用。
* **生成 SSA 指令来检查 `i` 的动态类型是否是 `string`。** 这通常涉及到比较接口的 `itab` 或 `type` 字段与 `string` 类型的反射信息。
* **生成条件分支指令：**
    * 如果断言成功，则将 `i` 的底层值（字符串 "hello" 的指针）赋值给 `s` 对应的 SSA 值，并将 `ok` 对应的 SSA 值设置为 true。
    * 如果断言失败，则将 `ok` 对应的 SSA 值设置为 false。
* **返回 `s` 和 `ok` 的 SSA 值。**

**命令行参数：**

这部分代码中涉及到了一些命令行参数的处理，主要体现在 `base.Flag` 和 `base.Debug` 的使用上：

* **`base.Flag.B != 0`:**  这个标志通常用于禁用边界检查。如果设置了这个标志，`boundsCheck` 函数会直接返回扩展后的索引，跳过实际的边界检查逻辑。这在性能敏感的场景下可能会被使用，但会牺牲安全性。

* **`base.Flag.Cfg.SpectreIndex`:**  用于启用针对 Spectre 漏洞的索引缓解措施。如果启用，`boundsCheck` 会在返回索引之前应用一个掩码 (`ssa.OpSpectreIndex` 或 `ssa.OpSpectreSliceIndex`)，以防止推测性执行导致越界访问。

* **`base.Debug.DisableNil != 0`:** 用于禁用 nil 检查。如果设置，`nilCheck` 函数会直接返回输入的指针，不做任何检查。

* **`base.Debug.TypeAssert > 0`:**  用于控制类型断言的调试输出。如果大于 0，则在类型断言被内联时会发出警告信息。

**使用者易犯错的点：**

由于这部分代码是 Go 编译器内部的实现，直接的用户代码不会涉及到这些函数调用。然而，理解这些机制可以帮助开发者避免一些常见的错误：

* **过度依赖隐式的 nil 检查:** 编译器可能会移除一些它认为不必要的 nil 检查（例如，当指针来自已知非 nil 的来源时）。开发者不应该假设所有的 nil 检查都会被保留。

* **忽略边界检查的性能影响:** 尽管边界检查是保证 Go 程序安全性的重要机制，但在某些性能 критичных 场景下，可能会考虑使用一些 unsafe 的操作来绕过检查（但这会带来安全风险，应谨慎使用）。理解 `-B` 标志的作用可以帮助分析性能瓶颈。

* **对类型断言的性能影响不了解:** 类型断言在运行时需要进行类型检查，可能会有性能开销。尤其是在循环中频繁进行类型断言时，需要考虑其对性能的影响。编译器可能会尝试内联一些简单的类型断言，但复杂的断言仍然需要在运行时处理。

**总结第 6 部分的功能：**

总的来说，`ssa.go` 的第 6 部分专注于将 Go 语言中一些更高级的特性（如切片、类型转换、类型断言）以及内置函数的操作转换为底层的 SSA 指令。它涵盖了安全性和性能优化的重要方面，例如边界检查、nil 检查以及针对特定硬件漏洞的缓解措施。这部分代码是 Go 编译器将高级语言语义映射到可执行代码的关键组成部分。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssagen/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```go
) != ir.ONAME {
		return false
	}
	return s.canSSAName(n.(*ir.Name)) && ssa.CanSSA(n.Type())
}

func (s *state) canSSAName(name *ir.Name) bool {
	if name.Addrtaken() || !name.OnStack() {
		return false
	}
	switch name.Class {
	case ir.PPARAMOUT:
		if s.hasdefer {
			// TODO: handle this case? Named return values must be
			// in memory so that the deferred function can see them.
			// Maybe do: if !strings.HasPrefix(n.String(), "~") { return false }
			// Or maybe not, see issue 18860.  Even unnamed return values
			// must be written back so if a defer recovers, the caller can see them.
			return false
		}
		if s.cgoUnsafeArgs {
			// Cgo effectively takes the address of all result args,
			// but the compiler can't see that.
			return false
		}
	}
	return true
	// TODO: try to make more variables SSAable?
}

// exprPtr evaluates n to a pointer and nil-checks it.
func (s *state) exprPtr(n ir.Node, bounded bool, lineno src.XPos) *ssa.Value {
	p := s.expr(n)
	if bounded || n.NonNil() {
		if s.f.Frontend().Debug_checknil() && lineno.Line() > 1 {
			s.f.Warnl(lineno, "removed nil check")
		}
		return p
	}
	p = s.nilCheck(p)
	return p
}

// nilCheck generates nil pointer checking code.
// Used only for automatically inserted nil checks,
// not for user code like 'x != nil'.
// Returns a "definitely not nil" copy of x to ensure proper ordering
// of the uses of the post-nilcheck pointer.
func (s *state) nilCheck(ptr *ssa.Value) *ssa.Value {
	if base.Debug.DisableNil != 0 || s.curfn.NilCheckDisabled() {
		return ptr
	}
	return s.newValue2(ssa.OpNilCheck, ptr.Type, ptr, s.mem())
}

// boundsCheck generates bounds checking code. Checks if 0 <= idx <[=] len, branches to exit if not.
// Starts a new block on return.
// On input, len must be converted to full int width and be nonnegative.
// Returns idx converted to full int width.
// If bounded is true then caller guarantees the index is not out of bounds
// (but boundsCheck will still extend the index to full int width).
func (s *state) boundsCheck(idx, len *ssa.Value, kind ssa.BoundsKind, bounded bool) *ssa.Value {
	idx = s.extendIndex(idx, len, kind, bounded)

	if bounded || base.Flag.B != 0 {
		// If bounded or bounds checking is flag-disabled, then no check necessary,
		// just return the extended index.
		//
		// Here, bounded == true if the compiler generated the index itself,
		// such as in the expansion of a slice initializer. These indexes are
		// compiler-generated, not Go program variables, so they cannot be
		// attacker-controlled, so we can omit Spectre masking as well.
		//
		// Note that we do not want to omit Spectre masking in code like:
		//
		//	if 0 <= i && i < len(x) {
		//		use(x[i])
		//	}
		//
		// Lucky for us, bounded==false for that code.
		// In that case (handled below), we emit a bound check (and Spectre mask)
		// and then the prove pass will remove the bounds check.
		// In theory the prove pass could potentially remove certain
		// Spectre masks, but it's very delicate and probably better
		// to be conservative and leave them all in.
		return idx
	}

	bNext := s.f.NewBlock(ssa.BlockPlain)
	bPanic := s.f.NewBlock(ssa.BlockExit)

	if !idx.Type.IsSigned() {
		switch kind {
		case ssa.BoundsIndex:
			kind = ssa.BoundsIndexU
		case ssa.BoundsSliceAlen:
			kind = ssa.BoundsSliceAlenU
		case ssa.BoundsSliceAcap:
			kind = ssa.BoundsSliceAcapU
		case ssa.BoundsSliceB:
			kind = ssa.BoundsSliceBU
		case ssa.BoundsSlice3Alen:
			kind = ssa.BoundsSlice3AlenU
		case ssa.BoundsSlice3Acap:
			kind = ssa.BoundsSlice3AcapU
		case ssa.BoundsSlice3B:
			kind = ssa.BoundsSlice3BU
		case ssa.BoundsSlice3C:
			kind = ssa.BoundsSlice3CU
		}
	}

	var cmp *ssa.Value
	if kind == ssa.BoundsIndex || kind == ssa.BoundsIndexU {
		cmp = s.newValue2(ssa.OpIsInBounds, types.Types[types.TBOOL], idx, len)
	} else {
		cmp = s.newValue2(ssa.OpIsSliceInBounds, types.Types[types.TBOOL], idx, len)
	}
	b := s.endBlock()
	b.Kind = ssa.BlockIf
	b.SetControl(cmp)
	b.Likely = ssa.BranchLikely
	b.AddEdgeTo(bNext)
	b.AddEdgeTo(bPanic)

	s.startBlock(bPanic)
	if Arch.LinkArch.Family == sys.Wasm {
		// TODO(khr): figure out how to do "register" based calling convention for bounds checks.
		// Should be similar to gcWriteBarrier, but I can't make it work.
		s.rtcall(BoundsCheckFunc[kind], false, nil, idx, len)
	} else {
		mem := s.newValue3I(ssa.OpPanicBounds, types.TypeMem, int64(kind), idx, len, s.mem())
		s.endBlock().SetControl(mem)
	}
	s.startBlock(bNext)

	// In Spectre index mode, apply an appropriate mask to avoid speculative out-of-bounds accesses.
	if base.Flag.Cfg.SpectreIndex {
		op := ssa.OpSpectreIndex
		if kind != ssa.BoundsIndex && kind != ssa.BoundsIndexU {
			op = ssa.OpSpectreSliceIndex
		}
		idx = s.newValue2(op, types.Types[types.TINT], idx, len)
	}

	return idx
}

// If cmp (a bool) is false, panic using the given function.
func (s *state) check(cmp *ssa.Value, fn *obj.LSym) {
	b := s.endBlock()
	b.Kind = ssa.BlockIf
	b.SetControl(cmp)
	b.Likely = ssa.BranchLikely
	bNext := s.f.NewBlock(ssa.BlockPlain)
	line := s.peekPos()
	pos := base.Ctxt.PosTable.Pos(line)
	fl := funcLine{f: fn, base: pos.Base(), line: pos.Line()}
	bPanic := s.panics[fl]
	if bPanic == nil {
		bPanic = s.f.NewBlock(ssa.BlockPlain)
		s.panics[fl] = bPanic
		s.startBlock(bPanic)
		// The panic call takes/returns memory to ensure that the right
		// memory state is observed if the panic happens.
		s.rtcall(fn, false, nil)
	}
	b.AddEdgeTo(bNext)
	b.AddEdgeTo(bPanic)
	s.startBlock(bNext)
}

func (s *state) intDivide(n ir.Node, a, b *ssa.Value) *ssa.Value {
	needcheck := true
	switch b.Op {
	case ssa.OpConst8, ssa.OpConst16, ssa.OpConst32, ssa.OpConst64:
		if b.AuxInt != 0 {
			needcheck = false
		}
	}
	if needcheck {
		// do a size-appropriate check for zero
		cmp := s.newValue2(s.ssaOp(ir.ONE, n.Type()), types.Types[types.TBOOL], b, s.zeroVal(n.Type()))
		s.check(cmp, ir.Syms.Panicdivide)
	}
	return s.newValue2(s.ssaOp(n.Op(), n.Type()), a.Type, a, b)
}

// rtcall issues a call to the given runtime function fn with the listed args.
// Returns a slice of results of the given result types.
// The call is added to the end of the current block.
// If returns is false, the block is marked as an exit block.
func (s *state) rtcall(fn *obj.LSym, returns bool, results []*types.Type, args ...*ssa.Value) []*ssa.Value {
	s.prevCall = nil
	// Write args to the stack
	off := base.Ctxt.Arch.FixedFrameSize
	var callArgs []*ssa.Value
	var callArgTypes []*types.Type

	for _, arg := range args {
		t := arg.Type
		off = types.RoundUp(off, t.Alignment())
		size := t.Size()
		callArgs = append(callArgs, arg)
		callArgTypes = append(callArgTypes, t)
		off += size
	}
	off = types.RoundUp(off, int64(types.RegSize))

	// Issue call
	var call *ssa.Value
	aux := ssa.StaticAuxCall(fn, s.f.ABIDefault.ABIAnalyzeTypes(callArgTypes, results))
	callArgs = append(callArgs, s.mem())
	call = s.newValue0A(ssa.OpStaticLECall, aux.LateExpansionResultType(), aux)
	call.AddArgs(callArgs...)
	s.vars[memVar] = s.newValue1I(ssa.OpSelectN, types.TypeMem, int64(len(results)), call)

	if !returns {
		// Finish block
		b := s.endBlock()
		b.Kind = ssa.BlockExit
		b.SetControl(call)
		call.AuxInt = off - base.Ctxt.Arch.FixedFrameSize
		if len(results) > 0 {
			s.Fatalf("panic call can't have results")
		}
		return nil
	}

	// Load results
	res := make([]*ssa.Value, len(results))
	for i, t := range results {
		off = types.RoundUp(off, t.Alignment())
		res[i] = s.resultOfCall(call, int64(i), t)
		off += t.Size()
	}
	off = types.RoundUp(off, int64(types.PtrSize))

	// Remember how much callee stack space we needed.
	call.AuxInt = off

	return res
}

// do *left = right for type t.
func (s *state) storeType(t *types.Type, left, right *ssa.Value, skip skipMask, leftIsStmt bool) {
	s.instrument(t, left, instrumentWrite)

	if skip == 0 && (!t.HasPointers() || ssa.IsStackAddr(left)) {
		// Known to not have write barrier. Store the whole type.
		s.vars[memVar] = s.newValue3Apos(ssa.OpStore, types.TypeMem, t, left, right, s.mem(), leftIsStmt)
		return
	}

	// store scalar fields first, so write barrier stores for
	// pointer fields can be grouped together, and scalar values
	// don't need to be live across the write barrier call.
	// TODO: if the writebarrier pass knows how to reorder stores,
	// we can do a single store here as long as skip==0.
	s.storeTypeScalars(t, left, right, skip)
	if skip&skipPtr == 0 && t.HasPointers() {
		s.storeTypePtrs(t, left, right)
	}
}

// do *left = right for all scalar (non-pointer) parts of t.
func (s *state) storeTypeScalars(t *types.Type, left, right *ssa.Value, skip skipMask) {
	switch {
	case t.IsBoolean() || t.IsInteger() || t.IsFloat() || t.IsComplex():
		s.store(t, left, right)
	case t.IsPtrShaped():
		if t.IsPtr() && t.Elem().NotInHeap() {
			s.store(t, left, right) // see issue 42032
		}
		// otherwise, no scalar fields.
	case t.IsString():
		if skip&skipLen != 0 {
			return
		}
		len := s.newValue1(ssa.OpStringLen, types.Types[types.TINT], right)
		lenAddr := s.newValue1I(ssa.OpOffPtr, s.f.Config.Types.IntPtr, s.config.PtrSize, left)
		s.store(types.Types[types.TINT], lenAddr, len)
	case t.IsSlice():
		if skip&skipLen == 0 {
			len := s.newValue1(ssa.OpSliceLen, types.Types[types.TINT], right)
			lenAddr := s.newValue1I(ssa.OpOffPtr, s.f.Config.Types.IntPtr, s.config.PtrSize, left)
			s.store(types.Types[types.TINT], lenAddr, len)
		}
		if skip&skipCap == 0 {
			cap := s.newValue1(ssa.OpSliceCap, types.Types[types.TINT], right)
			capAddr := s.newValue1I(ssa.OpOffPtr, s.f.Config.Types.IntPtr, 2*s.config.PtrSize, left)
			s.store(types.Types[types.TINT], capAddr, cap)
		}
	case t.IsInterface():
		// itab field doesn't need a write barrier (even though it is a pointer).
		itab := s.newValue1(ssa.OpITab, s.f.Config.Types.BytePtr, right)
		s.store(types.Types[types.TUINTPTR], left, itab)
	case t.IsStruct():
		n := t.NumFields()
		for i := 0; i < n; i++ {
			ft := t.FieldType(i)
			addr := s.newValue1I(ssa.OpOffPtr, ft.PtrTo(), t.FieldOff(i), left)
			val := s.newValue1I(ssa.OpStructSelect, ft, int64(i), right)
			s.storeTypeScalars(ft, addr, val, 0)
		}
	case t.IsArray() && t.NumElem() == 0:
		// nothing
	case t.IsArray() && t.NumElem() == 1:
		s.storeTypeScalars(t.Elem(), left, s.newValue1I(ssa.OpArraySelect, t.Elem(), 0, right), 0)
	default:
		s.Fatalf("bad write barrier type %v", t)
	}
}

// do *left = right for all pointer parts of t.
func (s *state) storeTypePtrs(t *types.Type, left, right *ssa.Value) {
	switch {
	case t.IsPtrShaped():
		if t.IsPtr() && t.Elem().NotInHeap() {
			break // see issue 42032
		}
		s.store(t, left, right)
	case t.IsString():
		ptr := s.newValue1(ssa.OpStringPtr, s.f.Config.Types.BytePtr, right)
		s.store(s.f.Config.Types.BytePtr, left, ptr)
	case t.IsSlice():
		elType := types.NewPtr(t.Elem())
		ptr := s.newValue1(ssa.OpSlicePtr, elType, right)
		s.store(elType, left, ptr)
	case t.IsInterface():
		// itab field is treated as a scalar.
		idata := s.newValue1(ssa.OpIData, s.f.Config.Types.BytePtr, right)
		idataAddr := s.newValue1I(ssa.OpOffPtr, s.f.Config.Types.BytePtrPtr, s.config.PtrSize, left)
		s.store(s.f.Config.Types.BytePtr, idataAddr, idata)
	case t.IsStruct():
		n := t.NumFields()
		for i := 0; i < n; i++ {
			ft := t.FieldType(i)
			if !ft.HasPointers() {
				continue
			}
			addr := s.newValue1I(ssa.OpOffPtr, ft.PtrTo(), t.FieldOff(i), left)
			val := s.newValue1I(ssa.OpStructSelect, ft, int64(i), right)
			s.storeTypePtrs(ft, addr, val)
		}
	case t.IsArray() && t.NumElem() == 0:
		// nothing
	case t.IsArray() && t.NumElem() == 1:
		s.storeTypePtrs(t.Elem(), left, s.newValue1I(ssa.OpArraySelect, t.Elem(), 0, right))
	default:
		s.Fatalf("bad write barrier type %v", t)
	}
}

// putArg evaluates n for the purpose of passing it as an argument to a function and returns the value for the call.
func (s *state) putArg(n ir.Node, t *types.Type) *ssa.Value {
	var a *ssa.Value
	if !ssa.CanSSA(t) {
		a = s.newValue2(ssa.OpDereference, t, s.addr(n), s.mem())
	} else {
		a = s.expr(n)
	}
	return a
}

func (s *state) storeArgWithBase(n ir.Node, t *types.Type, base *ssa.Value, off int64) {
	pt := types.NewPtr(t)
	var addr *ssa.Value
	if base == s.sp {
		// Use special routine that avoids allocation on duplicate offsets.
		addr = s.constOffPtrSP(pt, off)
	} else {
		addr = s.newValue1I(ssa.OpOffPtr, pt, off, base)
	}

	if !ssa.CanSSA(t) {
		a := s.addr(n)
		s.move(t, addr, a)
		return
	}

	a := s.expr(n)
	s.storeType(t, addr, a, 0, false)
}

// slice computes the slice v[i:j:k] and returns ptr, len, and cap of result.
// i,j,k may be nil, in which case they are set to their default value.
// v may be a slice, string or pointer to an array.
func (s *state) slice(v, i, j, k *ssa.Value, bounded bool) (p, l, c *ssa.Value) {
	t := v.Type
	var ptr, len, cap *ssa.Value
	switch {
	case t.IsSlice():
		ptr = s.newValue1(ssa.OpSlicePtr, types.NewPtr(t.Elem()), v)
		len = s.newValue1(ssa.OpSliceLen, types.Types[types.TINT], v)
		cap = s.newValue1(ssa.OpSliceCap, types.Types[types.TINT], v)
	case t.IsString():
		ptr = s.newValue1(ssa.OpStringPtr, types.NewPtr(types.Types[types.TUINT8]), v)
		len = s.newValue1(ssa.OpStringLen, types.Types[types.TINT], v)
		cap = len
	case t.IsPtr():
		if !t.Elem().IsArray() {
			s.Fatalf("bad ptr to array in slice %v\n", t)
		}
		nv := s.nilCheck(v)
		ptr = s.newValue1(ssa.OpCopy, types.NewPtr(t.Elem().Elem()), nv)
		len = s.constInt(types.Types[types.TINT], t.Elem().NumElem())
		cap = len
	default:
		s.Fatalf("bad type in slice %v\n", t)
	}

	// Set default values
	if i == nil {
		i = s.constInt(types.Types[types.TINT], 0)
	}
	if j == nil {
		j = len
	}
	three := true
	if k == nil {
		three = false
		k = cap
	}

	// Panic if slice indices are not in bounds.
	// Make sure we check these in reverse order so that we're always
	// comparing against a value known to be nonnegative. See issue 28797.
	if three {
		if k != cap {
			kind := ssa.BoundsSlice3Alen
			if t.IsSlice() {
				kind = ssa.BoundsSlice3Acap
			}
			k = s.boundsCheck(k, cap, kind, bounded)
		}
		if j != k {
			j = s.boundsCheck(j, k, ssa.BoundsSlice3B, bounded)
		}
		i = s.boundsCheck(i, j, ssa.BoundsSlice3C, bounded)
	} else {
		if j != k {
			kind := ssa.BoundsSliceAlen
			if t.IsSlice() {
				kind = ssa.BoundsSliceAcap
			}
			j = s.boundsCheck(j, k, kind, bounded)
		}
		i = s.boundsCheck(i, j, ssa.BoundsSliceB, bounded)
	}

	// Word-sized integer operations.
	subOp := s.ssaOp(ir.OSUB, types.Types[types.TINT])
	mulOp := s.ssaOp(ir.OMUL, types.Types[types.TINT])
	andOp := s.ssaOp(ir.OAND, types.Types[types.TINT])

	// Calculate the length (rlen) and capacity (rcap) of the new slice.
	// For strings the capacity of the result is unimportant. However,
	// we use rcap to test if we've generated a zero-length slice.
	// Use length of strings for that.
	rlen := s.newValue2(subOp, types.Types[types.TINT], j, i)
	rcap := rlen
	if j != k && !t.IsString() {
		rcap = s.newValue2(subOp, types.Types[types.TINT], k, i)
	}

	if (i.Op == ssa.OpConst64 || i.Op == ssa.OpConst32) && i.AuxInt == 0 {
		// No pointer arithmetic necessary.
		return ptr, rlen, rcap
	}

	// Calculate the base pointer (rptr) for the new slice.
	//
	// Generate the following code assuming that indexes are in bounds.
	// The masking is to make sure that we don't generate a slice
	// that points to the next object in memory. We cannot just set
	// the pointer to nil because then we would create a nil slice or
	// string.
	//
	//     rcap = k - i
	//     rlen = j - i
	//     rptr = ptr + (mask(rcap) & (i * stride))
	//
	// Where mask(x) is 0 if x==0 and -1 if x>0 and stride is the width
	// of the element type.
	stride := s.constInt(types.Types[types.TINT], ptr.Type.Elem().Size())

	// The delta is the number of bytes to offset ptr by.
	delta := s.newValue2(mulOp, types.Types[types.TINT], i, stride)

	// If we're slicing to the point where the capacity is zero,
	// zero out the delta.
	mask := s.newValue1(ssa.OpSlicemask, types.Types[types.TINT], rcap)
	delta = s.newValue2(andOp, types.Types[types.TINT], delta, mask)

	// Compute rptr = ptr + delta.
	rptr := s.newValue2(ssa.OpAddPtr, ptr.Type, ptr, delta)

	return rptr, rlen, rcap
}

type u642fcvtTab struct {
	leq, cvt2F, and, rsh, or, add ssa.Op
	one                           func(*state, *types.Type, int64) *ssa.Value
}

var u64_f64 = u642fcvtTab{
	leq:   ssa.OpLeq64,
	cvt2F: ssa.OpCvt64to64F,
	and:   ssa.OpAnd64,
	rsh:   ssa.OpRsh64Ux64,
	or:    ssa.OpOr64,
	add:   ssa.OpAdd64F,
	one:   (*state).constInt64,
}

var u64_f32 = u642fcvtTab{
	leq:   ssa.OpLeq64,
	cvt2F: ssa.OpCvt64to32F,
	and:   ssa.OpAnd64,
	rsh:   ssa.OpRsh64Ux64,
	or:    ssa.OpOr64,
	add:   ssa.OpAdd32F,
	one:   (*state).constInt64,
}

func (s *state) uint64Tofloat64(n ir.Node, x *ssa.Value, ft, tt *types.Type) *ssa.Value {
	return s.uint64Tofloat(&u64_f64, n, x, ft, tt)
}

func (s *state) uint64Tofloat32(n ir.Node, x *ssa.Value, ft, tt *types.Type) *ssa.Value {
	return s.uint64Tofloat(&u64_f32, n, x, ft, tt)
}

func (s *state) uint64Tofloat(cvttab *u642fcvtTab, n ir.Node, x *ssa.Value, ft, tt *types.Type) *ssa.Value {
	// if x >= 0 {
	//    result = (floatY) x
	// } else {
	// 	  y = uintX(x) ; y = x & 1
	// 	  z = uintX(x) ; z = z >> 1
	// 	  z = z | y
	// 	  result = floatY(z)
	// 	  result = result + result
	// }
	//
	// Code borrowed from old code generator.
	// What's going on: large 64-bit "unsigned" looks like
	// negative number to hardware's integer-to-float
	// conversion. However, because the mantissa is only
	// 63 bits, we don't need the LSB, so instead we do an
	// unsigned right shift (divide by two), convert, and
	// double. However, before we do that, we need to be
	// sure that we do not lose a "1" if that made the
	// difference in the resulting rounding. Therefore, we
	// preserve it, and OR (not ADD) it back in. The case
	// that matters is when the eleven discarded bits are
	// equal to 10000000001; that rounds up, and the 1 cannot
	// be lost else it would round down if the LSB of the
	// candidate mantissa is 0.
	cmp := s.newValue2(cvttab.leq, types.Types[types.TBOOL], s.zeroVal(ft), x)
	b := s.endBlock()
	b.Kind = ssa.BlockIf
	b.SetControl(cmp)
	b.Likely = ssa.BranchLikely

	bThen := s.f.NewBlock(ssa.BlockPlain)
	bElse := s.f.NewBlock(ssa.BlockPlain)
	bAfter := s.f.NewBlock(ssa.BlockPlain)

	b.AddEdgeTo(bThen)
	s.startBlock(bThen)
	a0 := s.newValue1(cvttab.cvt2F, tt, x)
	s.vars[n] = a0
	s.endBlock()
	bThen.AddEdgeTo(bAfter)

	b.AddEdgeTo(bElse)
	s.startBlock(bElse)
	one := cvttab.one(s, ft, 1)
	y := s.newValue2(cvttab.and, ft, x, one)
	z := s.newValue2(cvttab.rsh, ft, x, one)
	z = s.newValue2(cvttab.or, ft, z, y)
	a := s.newValue1(cvttab.cvt2F, tt, z)
	a1 := s.newValue2(cvttab.add, tt, a, a)
	s.vars[n] = a1
	s.endBlock()
	bElse.AddEdgeTo(bAfter)

	s.startBlock(bAfter)
	return s.variable(n, n.Type())
}

type u322fcvtTab struct {
	cvtI2F, cvtF2F ssa.Op
}

var u32_f64 = u322fcvtTab{
	cvtI2F: ssa.OpCvt32to64F,
	cvtF2F: ssa.OpCopy,
}

var u32_f32 = u322fcvtTab{
	cvtI2F: ssa.OpCvt32to32F,
	cvtF2F: ssa.OpCvt64Fto32F,
}

func (s *state) uint32Tofloat64(n ir.Node, x *ssa.Value, ft, tt *types.Type) *ssa.Value {
	return s.uint32Tofloat(&u32_f64, n, x, ft, tt)
}

func (s *state) uint32Tofloat32(n ir.Node, x *ssa.Value, ft, tt *types.Type) *ssa.Value {
	return s.uint32Tofloat(&u32_f32, n, x, ft, tt)
}

func (s *state) uint32Tofloat(cvttab *u322fcvtTab, n ir.Node, x *ssa.Value, ft, tt *types.Type) *ssa.Value {
	// if x >= 0 {
	// 	result = floatY(x)
	// } else {
	// 	result = floatY(float64(x) + (1<<32))
	// }
	cmp := s.newValue2(ssa.OpLeq32, types.Types[types.TBOOL], s.zeroVal(ft), x)
	b := s.endBlock()
	b.Kind = ssa.BlockIf
	b.SetControl(cmp)
	b.Likely = ssa.BranchLikely

	bThen := s.f.NewBlock(ssa.BlockPlain)
	bElse := s.f.NewBlock(ssa.BlockPlain)
	bAfter := s.f.NewBlock(ssa.BlockPlain)

	b.AddEdgeTo(bThen)
	s.startBlock(bThen)
	a0 := s.newValue1(cvttab.cvtI2F, tt, x)
	s.vars[n] = a0
	s.endBlock()
	bThen.AddEdgeTo(bAfter)

	b.AddEdgeTo(bElse)
	s.startBlock(bElse)
	a1 := s.newValue1(ssa.OpCvt32to64F, types.Types[types.TFLOAT64], x)
	twoToThe32 := s.constFloat64(types.Types[types.TFLOAT64], float64(1<<32))
	a2 := s.newValue2(ssa.OpAdd64F, types.Types[types.TFLOAT64], a1, twoToThe32)
	a3 := s.newValue1(cvttab.cvtF2F, tt, a2)

	s.vars[n] = a3
	s.endBlock()
	bElse.AddEdgeTo(bAfter)

	s.startBlock(bAfter)
	return s.variable(n, n.Type())
}

// referenceTypeBuiltin generates code for the len/cap builtins for maps and channels.
func (s *state) referenceTypeBuiltin(n *ir.UnaryExpr, x *ssa.Value) *ssa.Value {
	if !n.X.Type().IsMap() && !n.X.Type().IsChan() {
		s.Fatalf("node must be a map or a channel")
	}
	if n.X.Type().IsChan() && n.Op() == ir.OLEN {
		s.Fatalf("cannot inline len(chan)") // must use runtime.chanlen now
	}
	if n.X.Type().IsChan() && n.Op() == ir.OCAP {
		s.Fatalf("cannot inline cap(chan)") // must use runtime.chancap now
	}
	if n.X.Type().IsMap() && n.Op() == ir.OCAP {
		s.Fatalf("cannot inline cap(map)") // cap(map) does not exist
	}
	// if n == nil {
	//   return 0
	// } else {
	//   // len, the actual loadType depends
	//   return int(*((*loadType)n))
	//   // cap (chan only, not used for now)
	//   return *(((*int)n)+1)
	// }
	lenType := n.Type()
	nilValue := s.constNil(types.Types[types.TUINTPTR])
	cmp := s.newValue2(ssa.OpEqPtr, types.Types[types.TBOOL], x, nilValue)
	b := s.endBlock()
	b.Kind = ssa.BlockIf
	b.SetControl(cmp)
	b.Likely = ssa.BranchUnlikely

	bThen := s.f.NewBlock(ssa.BlockPlain)
	bElse := s.f.NewBlock(ssa.BlockPlain)
	bAfter := s.f.NewBlock(ssa.BlockPlain)

	// length/capacity of a nil map/chan is zero
	b.AddEdgeTo(bThen)
	s.startBlock(bThen)
	s.vars[n] = s.zeroVal(lenType)
	s.endBlock()
	bThen.AddEdgeTo(bAfter)

	b.AddEdgeTo(bElse)
	s.startBlock(bElse)
	switch n.Op() {
	case ir.OLEN:
		if buildcfg.Experiment.SwissMap && n.X.Type().IsMap() {
			// length is stored in the first word.
			loadType := reflectdata.SwissMapType().Field(0).Type // uint64
			load := s.load(loadType, x)
			s.vars[n] = s.conv(nil, load, loadType, lenType) // integer conversion doesn't need Node
		} else {
			// length is stored in the first word for map/chan
			s.vars[n] = s.load(lenType, x)
		}
	case ir.OCAP:
		// capacity is stored in the second word for chan
		sw := s.newValue1I(ssa.OpOffPtr, lenType.PtrTo(), lenType.Size(), x)
		s.vars[n] = s.load(lenType, sw)
	default:
		s.Fatalf("op must be OLEN or OCAP")
	}
	s.endBlock()
	bElse.AddEdgeTo(bAfter)

	s.startBlock(bAfter)
	return s.variable(n, lenType)
}

type f2uCvtTab struct {
	ltf, cvt2U, subf, or ssa.Op
	floatValue           func(*state, *types.Type, float64) *ssa.Value
	intValue             func(*state, *types.Type, int64) *ssa.Value
	cutoff               uint64
}

var f32_u64 = f2uCvtTab{
	ltf:        ssa.OpLess32F,
	cvt2U:      ssa.OpCvt32Fto64,
	subf:       ssa.OpSub32F,
	or:         ssa.OpOr64,
	floatValue: (*state).constFloat32,
	intValue:   (*state).constInt64,
	cutoff:     1 << 63,
}

var f64_u64 = f2uCvtTab{
	ltf:        ssa.OpLess64F,
	cvt2U:      ssa.OpCvt64Fto64,
	subf:       ssa.OpSub64F,
	or:         ssa.OpOr64,
	floatValue: (*state).constFloat64,
	intValue:   (*state).constInt64,
	cutoff:     1 << 63,
}

var f32_u32 = f2uCvtTab{
	ltf:        ssa.OpLess32F,
	cvt2U:      ssa.OpCvt32Fto32,
	subf:       ssa.OpSub32F,
	or:         ssa.OpOr32,
	floatValue: (*state).constFloat32,
	intValue:   func(s *state, t *types.Type, v int64) *ssa.Value { return s.constInt32(t, int32(v)) },
	cutoff:     1 << 31,
}

var f64_u32 = f2uCvtTab{
	ltf:        ssa.OpLess64F,
	cvt2U:      ssa.OpCvt64Fto32,
	subf:       ssa.OpSub64F,
	or:         ssa.OpOr32,
	floatValue: (*state).constFloat64,
	intValue:   func(s *state, t *types.Type, v int64) *ssa.Value { return s.constInt32(t, int32(v)) },
	cutoff:     1 << 31,
}

func (s *state) float32ToUint64(n ir.Node, x *ssa.Value, ft, tt *types.Type) *ssa.Value {
	return s.floatToUint(&f32_u64, n, x, ft, tt)
}
func (s *state) float64ToUint64(n ir.Node, x *ssa.Value, ft, tt *types.Type) *ssa.Value {
	return s.floatToUint(&f64_u64, n, x, ft, tt)
}

func (s *state) float32ToUint32(n ir.Node, x *ssa.Value, ft, tt *types.Type) *ssa.Value {
	return s.floatToUint(&f32_u32, n, x, ft, tt)
}

func (s *state) float64ToUint32(n ir.Node, x *ssa.Value, ft, tt *types.Type) *ssa.Value {
	return s.floatToUint(&f64_u32, n, x, ft, tt)
}

func (s *state) floatToUint(cvttab *f2uCvtTab, n ir.Node, x *ssa.Value, ft, tt *types.Type) *ssa.Value {
	// cutoff:=1<<(intY_Size-1)
	// if x < floatX(cutoff) {
	// 	result = uintY(x)
	// } else {
	// 	y = x - floatX(cutoff)
	// 	z = uintY(y)
	// 	result = z | -(cutoff)
	// }
	cutoff := cvttab.floatValue(s, ft, float64(cvttab.cutoff))
	cmp := s.newValue2(cvttab.ltf, types.Types[types.TBOOL], x, cutoff)
	b := s.endBlock()
	b.Kind = ssa.BlockIf
	b.SetControl(cmp)
	b.Likely = ssa.BranchLikely

	bThen := s.f.NewBlock(ssa.BlockPlain)
	bElse := s.f.NewBlock(ssa.BlockPlain)
	bAfter := s.f.NewBlock(ssa.BlockPlain)

	b.AddEdgeTo(bThen)
	s.startBlock(bThen)
	a0 := s.newValue1(cvttab.cvt2U, tt, x)
	s.vars[n] = a0
	s.endBlock()
	bThen.AddEdgeTo(bAfter)

	b.AddEdgeTo(bElse)
	s.startBlock(bElse)
	y := s.newValue2(cvttab.subf, ft, x, cutoff)
	y = s.newValue1(cvttab.cvt2U, tt, y)
	z := cvttab.intValue(s, tt, int64(-cvttab.cutoff))
	a1 := s.newValue2(cvttab.or, tt, y, z)
	s.vars[n] = a1
	s.endBlock()
	bElse.AddEdgeTo(bAfter)

	s.startBlock(bAfter)
	return s.variable(n, n.Type())
}

// dottype generates SSA for a type assertion node.
// commaok indicates whether to panic or return a bool.
// If commaok is false, resok will be nil.
func (s *state) dottype(n *ir.TypeAssertExpr, commaok bool) (res, resok *ssa.Value) {
	iface := s.expr(n.X)              // input interface
	target := s.reflectType(n.Type()) // target type
	var targetItab *ssa.Value
	if n.ITab != nil {
		targetItab = s.expr(n.ITab)
	}
	return s.dottype1(n.Pos(), n.X.Type(), n.Type(), iface, nil, target, targetItab, commaok, n.Descriptor)
}

func (s *state) dynamicDottype(n *ir.DynamicTypeAssertExpr, commaok bool) (res, resok *ssa.Value) {
	iface := s.expr(n.X)
	var source, target, targetItab *ssa.Value
	if n.SrcRType != nil {
		source = s.expr(n.SrcRType)
	}
	if !n.X.Type().IsEmptyInterface() && !n.Type().IsInterface() {
		byteptr := s.f.Config.Types.BytePtr
		targetItab = s.expr(n.ITab)
		// TODO(mdempsky): Investigate whether compiling n.RType could be
		// better than loading itab.typ.
		target = s.load(byteptr, s.newValue1I(ssa.OpOffPtr, byteptr, rttype.ITab.OffsetOf("Type"), targetItab))
	} else {
		target = s.expr(n.RType)
	}
	return s.dottype1(n.Pos(), n.X.Type(), n.Type(), iface, source, target, targetItab, commaok, nil)
}

// dottype1 implements a x.(T) operation. iface is the argument (x), dst is the type we're asserting to (T)
// and src is the type we're asserting from.
// source is the *runtime._type of src
// target is the *runtime._type of dst.
// If src is a nonempty interface and dst is not an interface, targetItab is an itab representing (dst, src). Otherwise it is nil.
// commaok is true if the caller wants a boolean success value. Otherwise, the generated code panics if the conversion fails.
// descriptor is a compiler-allocated internal/abi.TypeAssert whose address is passed to runtime.typeAssert when
// the target type is a compile-time-known non-empty interface. It may be nil.
func (s *state) dottype1(pos src.XPos, src, dst *types.Type, iface, source, target, targetItab *ssa.Value, commaok bool, descriptor *obj.LSym) (res, resok *ssa.Value) {
	typs := s.f.Config.Types
	byteptr := typs.BytePtr
	if dst.IsInterface() {
		if dst.IsEmptyInterface() {
			// Converting to an empty interface.
			// Input could be an empty or nonempty interface.
			if base.Debug.TypeAssert > 0 {
				base.WarnfAt(pos, "type assertion inlined")
			}

			// Get itab/type field from input.
			itab := s.newValue1(ssa.OpITab, byteptr, iface)
			// Conversion succeeds iff that field is not nil.
			cond := s.newValue2(ssa.OpNeqPtr, types.Types[types.TBOOL], itab, s.constNil(byteptr))

			if src.IsEmptyInterface() && commaok {
				// Converting empty interface to empty interface with ,ok is just a nil check.
				return iface, cond
			}

			// Branch on nilness.
			b := s.endBlock()
			b.Kind = ssa.BlockIf
			b.SetControl(cond)
			b.Likely = ssa.BranchLikely
			bOk := s.f.NewBlock(ssa.BlockPlain)
			bFail := s.f.NewBlock(ssa.BlockPlain)
			b.AddEdgeTo(bOk)
			b.AddEdgeTo(bFail)

			if !commaok {
				// On failure, panic by calling panicnildottype.
				s.startBlock(bFail)
				s.rtcall(ir.Syms.Panicnildottype, false, nil, target)

				// On success, return (perhaps modified) input interface.
				s.startBlock(bOk)
				if src.IsEmptyInterface() {
					res = iface // Use input interface unchanged.
					return
				}
				// Load type out of itab, build interface with existing idata.
				off := s.newValue1I(ssa.OpOffPtr, byteptr, rttype.ITab.OffsetOf("Type"), itab)
				typ := s.load(byteptr, off)
				idata := s.newValue1(ssa.OpIData, byteptr, iface)
				res = s.newValue2(ssa.OpIMake, dst, typ, idata)
				return
			}

			s.startBlock(bOk)
			// nonempty -> empty
			// Need to load type from itab
			off := s.newValue1I(ssa.OpOffPtr, byteptr, rttype.ITab.OffsetOf("Type"), itab)
			s.vars[typVar] = s.load(byteptr, off)
			s.endBlock()

			// itab is nil, might as well use that as the nil result.
			s.startBlock(bFail)
			s.vars[typVar] = itab
			s.endBlock()

			// Merge point.
			bEnd := s.f.NewBlock(ssa.BlockPlain)
			bOk.AddEdgeTo(bEnd)
			bFail.AddEdgeTo(bEnd)
			s.startBlock(bEnd)
			idata := s.newValue1(ssa.OpIData, byteptr, iface)
			res = s.newValue2(ssa.OpIMake, dst, s.variable(typVar, byteptr), idata)
			resok = cond
			delete(s.vars, typVar) // no practical effect, just to indicate typVar is no longer live.
			return
		}
		// converting to a nonempty interface needs a runtime call.
		if base.Debug.TypeAssert > 0 {
			base.WarnfAt(pos, "type assertion not inlined")
		}

		itab := s.newValue1(ssa.OpITab, byteptr, iface)
		data := s.newValue1(ssa.OpIData, types.Types[types.TUNSAFEPTR], iface)

		// First, check for nil.
		bNil := s.f.NewBlock(ssa.BlockPlain)
		bNonNil := s.f.NewBlock(ssa.BlockPlain)
		bMerge := s.f.NewBlock(ssa.BlockPlain)
		cond := s.newValue2(ssa.OpNeqPtr, types.Types[types.TBOOL], itab, s.constNil(byteptr))
		b := s.endBlock()
		b.Kind = ssa.BlockIf
		b.SetControl(cond)
		b.Likely = ssa.BranchLikely
		b.AddEdgeTo(bNonNil)
		b.AddEdgeTo(bNil)

		s.startBlock(bNil)
		if commaok {
			s.vars[typVar] = itab // which will be nil
			b := s.endBlock()
			b.AddEdgeTo(bMerge)
		} else {
			// Panic if input is nil.
			s.rtcall(ir.Syms.Panicnildottype, false, nil, target)
		}

		// Get typ, possibly by loading out of itab.
		s.startBlock(bNonNil)
		typ := itab
		if !src.IsEmptyInterface() {
			typ = s.load(byteptr, s.newValue1I(ssa.OpOffPtr, byteptr, rttype.ITab.OffsetOf("Type"), itab))
		}

		// Check the cache first.
		var d *ssa.Value
		if descriptor != nil {
			d = s.newValue1A(ssa.OpAddr, byteptr, descriptor, s.sb)
			if base.Flag.N == 0 && rtabi.UseInterfaceSwitchCache(Arch.LinkArch.Name) {
				// Note: we can only use the cache if we have the right atomic load instruction.
				// Double-check that here.
				if intrinsics.lookup(Arch.LinkArch.Arch, "internal/runtime/atomic", "Loadp") == nil {
					s.Fatalf("atomic load not available")
				}
				// Pick right size ops.
				var mul, and, add, zext ssa.Op
				if s.config.PtrSize == 4 {
					mul = ssa.OpMul32
					and = ssa.OpAnd32
					add = ssa.OpAdd32
					zext = ssa.OpCopy
				} else {
					mul = ssa.OpMul64
					and = ssa.OpAnd64
					add = ssa.OpAdd64
					zext = ssa.OpZeroExt32to64
				}

				loopHead := s.f.NewBlock(ssa.BlockPlain)
				loopBody := s.f.NewBlock(ssa.BlockPlain)
				cacheHit := s.f.NewBlock(ssa.BlockPlain)
				cacheMiss := s.f.NewBlock(ssa.BlockPlain)

				// Load cache pointer out of descriptor, with an atomic load so
				// we ensure that we see a fully written cache.
				atomicLoad := s.newValue2(ssa.OpAtomicLoadPtr, types.NewTuple(typs.BytePtr, types.TypeMem), d, s.mem())
				cache := s.newValue1(ssa.OpSelect0, typs.BytePtr, atomicLoad)
				s.vars[memVar] = s.newValue1(ssa.OpSelect1, types.TypeMem, atomicLoad)

				// Load hash from type or itab.
				var hash *ssa.Value
				if src.IsEmptyInterface() {
					hash = s.newValue2(ssa.OpLoad, typs.UInt32, s.newValue1I(ssa.OpOffPtr, typs.UInt32Ptr, rttype.Type.OffsetOf("Hash"), typ), s.mem())
				} else {
					hash = s.newValue2(ssa.OpLoad, typs.UInt32, s.newValue1I(ssa.OpOffPtr, typs.UInt32Ptr, rttype.ITab.OffsetOf("Hash"), itab), s.mem())
				}
				hash = s.newValue1(zext, typs.Uintptr, hash)
				s.vars[hashVar] = hash
				// Load mask from cache.
				mask := s.newValue2(s
```