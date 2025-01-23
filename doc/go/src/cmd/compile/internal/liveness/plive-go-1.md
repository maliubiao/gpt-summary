Response:
Let's break down the thought process to arrive at the summary of `plive.go`'s functionality, given the provided code snippet.

**1. Initial Skim and Keyword Spotting:**

The first step is to quickly read through the code, looking for key terms and patterns. Words like "liveness", "clobber", "stack map", "pointer", "bitvec", "GC", "emit", "debug", and function names like `clobberWalk`, `clobberPtr`, `showlive`, `printDebug`, `emit`, `Compute`, `emitStackObjects`, `WriteFuncMap` jump out. These provide strong hints about the code's purpose.

**2. Focus on Major Functions:**

Next, I'd examine the main functions to understand their roles:

* **`clobberWalk` and `clobberPtr`:** The names suggest they are related to "clobbering" something, and the arguments (`ssa.Block`, `ir.Name`, `offset`, `types.Type`) indicate they operate on variables within a basic block of SSA (Static Single Assignment) form. The `types.Type` argument in `clobberWalk` and the recursive calls based on type kind suggest it handles different data structures containing pointers. `clobberPtr` seems to be the core operation, creating an `ssa.OpClobber`. *Hypothesis: These functions mark locations where pointers might be overwritten or invalidated.*

* **`showlive`:** The name and the use of `bitvec.BitVec` suggest this function deals with displaying liveness information. The checks for `base.Flag.Live` and the formatting of the output point to debugging or informational output. *Hypothesis: This function helps in visualizing which variables are live at certain points.*

* **`printbvec` and `printeffect`:** These functions appear to be helper functions for `printDebug`, responsible for formatting and printing bit vectors (likely representing liveness) and effects associated with values.

* **`printDebug`:** The name and the detailed output format clearly indicate this is a debugging function that presents a comprehensive view of the liveness analysis results, including block information, value effects, and stack maps.

* **`emit`:**  This function's purpose is strongly suggested by its name and the creation of `obj.LSym` (linker symbols). The comments about "encoding bitmaps" and "GCLocalsSym" point towards generating data structures for the garbage collector. *Hypothesis: This function transforms the liveness information into a format usable by the runtime.*

* **`Compute`:** This is a central function. It initializes the liveness analysis, runs the dataflow algorithm (`lv.solve()`), and calls `lv.emit()`. It also handles debugging output and updates the function cache. The return types (`Map`, `map[*ir.Name]bool`) and the parameter `stkptrsize` reinforce its role in the overall liveness analysis. *Hypothesis: This is the main entry point for computing liveness information for a function.*

* **`emitStackObjects`:** The name and the interaction with `ir.Name`, `FrameOffset`, and `reflectdata.GCSym` suggest it's responsible for generating metadata about stack-allocated objects that need garbage collection.

* **`isfat`:** The comments and the logic within this function indicate that it determines if a type requires multiple assignments for initialization, which is relevant to liveness analysis.

* **`WriteFuncMap`:** The name, the parameter `abiInfo`, and the creation of a symbol with ".args_stackmap" in its name suggest this function writes liveness information specifically for function arguments and return values, taking into account the function's ABI (Application Binary Interface).

**3. Connecting the Dots and Inferring the Overall Purpose:**

By examining the individual functions and their interactions, a clearer picture emerges:

* The code performs a liveness analysis on Go functions, specifically for pointer variables.
* It uses a dataflow algorithm to track which pointer variables are live (potentially pointing to valid memory) at different points in the code.
* The `clobber` functions handle cases where pointers might become invalid (e.g., due to assignments or function calls).
* The computed liveness information is used by the garbage collector to know which memory locations need to be scanned for live objects.
* The `emit` function generates the necessary metadata (stack maps) that the garbage collector uses at runtime.
* Debugging functions like `showlive` and `printDebug` are provided for development and verification.
* `WriteFuncMap` handles the specific case of arguments and return values.

**4. Formulating the Summary:**

Based on the above analysis, the core functionality can be summarized as:  This code implements a liveness analysis for pointer variables in Go functions. It determines which pointers are live at various points in the program. This information is crucial for the garbage collector to accurately identify live objects and reclaim unused memory. The code also includes debugging utilities and mechanisms to generate metadata for the runtime.

**5. Addressing Specific Parts of the Prompt (Reasoning, Examples, etc.):**

* **Reasoning about Go feature:** The connection to garbage collection is the most prominent aspect. Liveness analysis is a key technique for accurate garbage collection.
* **Go Code Example (Conceptual):** The provided example illustrates how the liveness analysis helps the garbage collector.
* **Command-line arguments:** The mention of `base.Flag.Live` points to a command-line flag controlling the verbosity of the liveness analysis output.
* **Common mistakes:** The example highlights a potential mistake related to assuming a pointer is always live after being set, which liveness analysis helps to avoid.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the individual bit manipulation aspects. However, stepping back and looking at the broader context of garbage collection and runtime support provided a more accurate understanding of the overall goal.
* The presence of functions like `WriteFuncMap` helped refine the understanding that the analysis isn't just about local variables but also about function arguments and return values.
*  Seeing the `emitStackObjects` function clarified that the analysis also plays a role in describing stack-allocated objects to the runtime.

This iterative process of skimming, focusing on key elements, connecting the dots, and refining the understanding leads to a comprehensive and accurate summary of the code's functionality.
这是Go语言编译器中 `go/src/cmd/compile/internal/liveness/plive.go` 文件的一部分，它实现了**指针活跃性分析 (Pointer Liveness Analysis)**。

**功能归纳 (第2部分):**

这部分代码主要负责以下功能：

1. **生成和输出活跃指针的位图数据 (Emit Liveness Bitmaps):**
   - `emit()` 函数负责将计算出的活跃性信息（存储在 `lv.stackMaps` 中）编码成两种位图数据结构：
     - `argsSym`:  存储函数参数中活跃指针的信息。
     - `liveSym`:  存储函数局部变量中活跃指针的信息。
   - 这些位图数据会被存储在 ELF 文件的 `.data` 段，供运行时垃圾回收器 (Garbage Collector, GC) 使用。
   - 位图的长度会根据函数参数和局部变量中可能包含的最大指针偏移量来确定。
   - 它遍历 `lv.stackMaps` 中的每个栈图，将对应的活跃变量信息填充到位图中。
   - 使用 `objw.Uint32` 和 `objw.BitVec` 等函数将位图数据写入到临时的 `obj.LSym` 结构中。
   - 最终，`emit()` 返回指向这些位图数据的 `obj.LSym` 符号。

2. **生成栈上对象的信息 (Emit Stack Objects):**
   - `emitStackObjects()` 函数负责生成关于栈上分配的、需要垃圾回收的对象的信息。
   - 它遍历函数的声明 (`lv.fn.Dcl`)，找出那些取地址 (`Addrtaken()`) 且未逃逸到堆 (`Esc() != ir.EscHeap`) 的变量。
   - 这些变量会被认为是栈上的对象。
   - 它将这些对象的信息（包括帧偏移、大小、指向类型信息的指针位图等）编码到名为 `<function_name>.stkobj` 的符号中。
   - 这些信息供运行时确定栈上哪些区域包含指针，需要被 GC 扫描。

3. **判断类型是否为“胖”类型 (isfat):**
   - `isfat(t *types.Type)` 函数判断一个类型 `t` 是否是“胖”类型。
   - “胖”类型指的是需要多次赋值才能完整初始化的类型，例如切片、字符串、接口，以及包含这些类型的数组或结构体。
   - 这个信息在活跃性分析中可能用于更精确地跟踪复杂类型的活跃性。

4. **为无函数体的函数写入参数和返回值的指针位图 (WriteFuncMap):**
   - `WriteFuncMap(fn *ir.Func, abiInfo *abi.ABIParamResultInfo)` 函数专门处理没有函数体的函数（通常是外部函数声明或接口方法）。
   - 它根据函数的 ABI 信息 (`abiInfo`)，确定参数和返回值中哪些位置包含指针。
   - 它创建一个位图，标记出这些指针位置。
   - 将该位图数据写入到名为 `<function_name>.args_stackmap` 的符号中。
   - 这使得即使没有函数体，GC 也能知道如何处理这些函数的参数和返回值。

**总结:**

这部分代码是 Go 语言编译器中指针活跃性分析的关键组成部分，其主要职责是将分析结果转换为运行时可用的数据结构。它生成了描述函数参数、局部变量和栈上对象的活跃指针信息的位图，以及其他必要的元数据，这些数据对于垃圾回收器的正确运行至关重要。 `emit()` 和 `emitStackObjects()` 是核心函数，负责将内存中的活跃性分析结果持久化到目标文件中，而 `isfat()` 和 `WriteFuncMap()` 则处理一些特定的辅助情况。

### 提示词
```
这是路径为go/src/cmd/compile/internal/liveness/plive.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
le
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
```