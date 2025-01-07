Response: My thinking process to arrive at the summary of the provided Go code went something like this:

1. **Understand the Goal:** The request asks for a summary of the Go code's functionality, inferring its purpose, providing Go code examples, explaining command-line parameters (if any), noting potential errors, and specifically stating this is part 3 of 4.

2. **Initial Scan for Keywords and Patterns:** I quickly scanned the code for recurring keywords and patterns that would hint at its function. I noticed:
    * `ssa`:  This strongly suggests involvement with Static Single Assignment form, a crucial intermediate representation in compilers.
    * `ir`:  Likely stands for Intermediate Representation, the Go compiler's AST.
    * `s.`:  Indicates methods belonging to a `state` struct, implying this code manages some compiler state during SSA generation.
    * Function names like `condBranch`, `assign`, `call`, `addr`, `storeType`, `slice`, `dottype`: These are indicative of core compiler tasks like handling conditional branches, assignments, function calls, address calculations, memory stores, slice operations, and type assertions.
    * Logic for `OANDAND`, `OOROR`, `ONOT`: These are Go language logical operators.
    * Handling of `defer` and `go`:  Keywords related to concurrency and deferred function calls.
    * `intrinsicCall`:  Indicates optimization through replacing function calls with simpler, equivalent code.
    * Operations on different data types (integers, floats, strings, slices, interfaces).
    * Runtime function calls (`rtcall`).
    * Bounds checking (`boundsCheck`).
    * Nil checks (`nilCheck`).
    * Handling of soft-float operations (`sfcall`).
    * Type conversions.

3. **Identify the Core Task:** Based on the frequent use of `ssa`, `ir`, and the nature of the operations being performed, I concluded that this code is responsible for **generating SSA (Static Single Assignment) form from the Go compiler's intermediate representation (IR).**

4. **Break Down Functionality into Key Areas:** I mentally grouped the observed functionalities into logical categories:
    * **Control Flow:**  Handling `if`, `&&`, `||`, `!` conditions using `condBranch`.
    * **Assignments:**  Implementing the `=` operator, handling different scenarios like SSA-able variables, struct field assignments, array assignments, and dereferencing.
    * **Function Calls:** Generating code for regular calls, `defer`, and `go` statements. This includes handling closures and interface calls.
    * **Memory Operations:**  Calculating addresses (`addr`), storing values (`storeType`), and performing memory moves.
    * **Built-in Functions and Operations:** Implementing `len`, `cap`, slicing, type assertions (`dottype`), and conversions.
    * **Error Handling/Safety:** Generating bounds checks and nil checks.
    * **Optimization:** Using intrinsic functions.
    * **Special Features:** Handling `defer` (open-coded defers).

5. **Infer Go Language Features:** By connecting the code's actions to specific Go constructs, I inferred the following Go language features are being implemented:
    * Boolean expressions and their short-circuiting behavior (`&&`, `||`, `!`).
    * Variable assignments, including assignments to struct fields and array elements.
    * Function calls, including methods on interfaces.
    * `defer` and `go` statements for managing function execution.
    * Built-in functions like `len` and `cap`.
    * Slicing operations on arrays, slices, and strings.
    * Type assertions.
    * Type conversions between different data types (integers, floats).

6. **Construct Go Code Examples:** For each key inferred Go feature, I created simple, illustrative Go code examples. I aimed for clarity and conciseness. For example, for boolean expressions, I showed a basic `if` statement with `&&`. For assignments, I covered simple variables, struct fields, and array elements.

7. **Address Specific Instructions:**
    * **Command-line parameters:** I noticed no explicit parsing of command-line flags within the provided code snippet. However, I included a general explanation about compiler flags influencing SSA generation.
    * **Code Inference (with assumptions):** My examples inherently involved code inference. The "assumptions" were the standard semantics of Go. The inputs were the Go code snippets, and the outputs were the *intended* SSA-level operations (though not the exact SSA code).
    * **User Errors:** I focused on the most likely mistake: incorrect slice indexing leading to panics.

8. **Synthesize the Summary:**  I combined the individual pieces of information into a cohesive summary, emphasizing the core function of SSA generation and the specific Go language features handled. I also included the detail about this being part 3 of 4.

9. **Refine and Organize:** I reviewed the entire summary for clarity, accuracy, and organization, ensuring the explanations were easy to understand and the examples were relevant. I used bolding and bullet points to improve readability.

This iterative process of scanning, identifying patterns, inferring functionality, creating examples, and then synthesizing and refining the information allowed me to arrive at the comprehensive summary provided earlier.
这是 `go/src/cmd/compile/internal/ssagen/ssa.go` 文件的一部分，它主要负责将 Go 语言的 **中间表示 (IR)** 转换为 **静态单赋值 (SSA) 形式**。这是 Go 编译器后端优化的关键步骤。

以下是这段代码的功能归纳：

**核心功能：将 Go 语言的特定 IR 节点转换为 SSA 代码。**

更具体地说，这段代码处理了以下类型的 IR 节点，并生成相应的 SSA 代码：

* **逻辑表达式 (`ir.OANDAND`, `ir.OOROR`, `ir.ONOT`):**  负责将 Go 语言中的逻辑运算符 `&&`, `||`, `!` 转换为 SSA 中的条件分支结构。它还考虑了分支预测的可能性 (`likely`) 来优化生成的代码。
* **类型转换 (`ir.OCONVNOP`):** 处理不需要实际操作的类型转换。
* **赋值语句:**  负责将 Go 语言中的赋值操作转换为 SSA 中的存储操作。它处理了不同类型的左值，包括：
    * **SSAable 变量 (`ir.ONAME`)**: 直接更新 SSA 的变量映射。
    * **结构体字段 (`ir.ODOT`)**: 创建新的结构体值并进行赋值。
    * **数组元素 (`ir.OINDEX` 针对数组)**: 创建新的数组值并进行赋值。
    * **非 SSAable 变量**: 计算地址并进行存储。
    * **通过指针解引用赋值 (`deref`)**:  执行内存到内存的复制或清零操作。
* **零值初始化:**  提供了 `zeroVal` 函数，用于生成各种 Go 数据类型的零值。
* **函数调用:** 提供了 `call` 函数，用于将 Go 语言的函数调用转换为 SSA 代码，支持：
    * **普通函数调用 (`callNormal`)**
    * **defer 调用 (`callDefer`, `callDeferStack`)**
    * **go 语句 (`callGo`)**
    * **尾调用优化 (`callTail`)**
    * 它还处理了接口调用 (`ir.OCALLINTER`) 和静态函数调用 (`ir.OCALLFUNC`)。
* **内置函数处理 (`intrinsicCall`)**:  尝试将一些 Go 内置函数（例如 `len`, `cap` 等）转换为更高效的 SSA 操作。
* **open-coded defer 处理 (`openDeferRecord`, `openDeferSave`, `openDeferExit`)**:  负责将 `defer` 语句转换为 SSA 代码，特别是在可以进行栈上 `defer` 优化的场景下。
* **地址计算 (`addr`)**:  负责计算各种 Go 表达式的内存地址，包括变量、数组元素、结构体字段、解引用等。
* **指针解引用 (`exprPtr`)**:  获取指针指向的值，并根据情况插入 nil 检查。
* **nil 检查 (`nilCheck`)**:  生成用于检查指针是否为 nil 的 SSA 代码。
* **边界检查 (`boundsCheck`)**:  为数组、切片等操作生成边界检查的 SSA 代码，防止越界访问。
* **运行时函数调用 (`rtcall`)**:  用于调用 Go 运行时的函数。
* **类型存储 (`storeType`, `storeTypeScalars`, `storeTypePtrs`)**:  将值存储到内存中，并处理带有指针的类型，可能需要插入写屏障。
* **参数传递 (`putArg`, `storeArgWithBase`)**:  处理函数调用的参数传递。
* **切片操作 (`slice`)**:  将 Go 语言的切片操作转换为 SSA 代码，包括计算新的指针、长度和容量。
* **类型断言 (`dottype`, `dynamicDottype`, `dottype1`)**:  将类型断言表达式转换为 SSA 代码，包括成功和失败的分支处理。
* **类型转换的特殊处理**:  针对浮点数和无符号整数之间的转换提供了特定的处理函数 (`uint64Tofloat`, `uint32Tofloat`, `floatToUint`) 以确保精度和正确性。
* **引用类型内置函数 (`referenceTypeBuiltin`)**:  处理 `len` 和 `cap` 对 map 和 channel 的调用。

**可以推理出它是什么 Go 语言功能的实现：**

这段代码是 Go 编译器中 **SSA 代码生成器** 的一部分，负责将 Go 语言的源代码翻译成可以在后续阶段进行优化的 SSA 中间表示。它涵盖了 Go 语言中控制流、赋值、函数调用、内存操作、类型转换和一些内置函数的 SSA 代码生成。

**Go 代码示例：**

假设输入以下 Go 代码片段：

```go
package main

func main() {
	x := 10
	y := 20
	if x > 5 && y < 30 {
		println("条件成立")
	}

	type MyStruct struct {
		A int
		B string
	}
	s := MyStruct{A: x, B: "hello"}
	s.A = 15

	arr := [3]int{1, 2, 3}
	arr[1] = 4

	z := &x
	*z = 25

	mySlice := []int{1, 2, 3, 4, 5}
	subSlice := mySlice[1:3]

	var i interface{} = "world"
	str, ok := i.(string)
	if ok {
		println(str)
	}
}
```

**假设的输入与输出（简化）：**

* **输入 (IR 节点):**  例如，对于 `x > 5 && y < 30`，会输入 `ir.OANDAND` 节点，其子节点为 `ir.OGT` 和 `ir.OLT`。
* **输出 (SSA 代码，简化表示):**
    ```
    // 对于 x > 5
    v1 = LocalAddr {x}
    v2 = Load v1
    v3 = ConstInt 5
    v4 = GreaterThan v2, v3
    // 跳转到中间块 mid 如果 v4 为真

    // 中间块 mid
    // 对于 y < 30
    v5 = LocalAddr {y}
    v6 = Load v5
    v7 = ConstInt 30
    v8 = LessThan v6, v7
    // 跳转到 yes 块如果 v8 为真，否则跳转到 no 块

    // yes 块 (条件成立)
    // ... println("条件成立") 的 SSA 代码

    // no 块 (条件不成立)
    // ...

    // 对于 s.A = 15
    v9 = LocalAddr {s}
    v10 = OffPtr v9, offsetof(MyStruct, A)
    v11 = ConstInt 15
    Store v10, v11

    // 对于 arr[1] = 4
    v12 = LocalAddr {arr}
    v13 = ConstInt 1
    v14 = PtrIndex v12, v13
    v15 = ConstInt 4
    Store v14, v15

    // ... 其他语句的 SSA 代码
    ```

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。但是，Go 编译器的命令行参数会影响 SSA 的生成过程。例如：

* `-N` (禁用优化):  会影响是否启用 SSA，如果禁用优化，可能就不会生成 SSA 代码。
* `-l` (禁用内联):  会影响函数调用是否被内联，从而影响生成的 SSA 代码。
* `-gcflags` 等标志可以传递给垃圾回收器，这可能会影响与内存管理相关的 SSA 代码生成。
* `-B` (禁用边界检查):  会影响是否生成边界检查的 SSA 代码。

**使用者易犯错的点：**

作为编译器开发者，在编写或修改这段代码时，容易犯以下错误：

* **不正确的类型处理:**  未能正确处理不同 Go 数据类型到 SSA 类型的映射，导致生成的 SSA 代码类型不匹配。
* **错误的地址计算:**  在计算内存地址时出现错误，导致存储或加载到错误的内存位置。
* **控制流逻辑错误:**  在将 Go 的控制流语句（如 `if`, `for`, `switch`）转换为 SSA 的基本块和跳转指令时出现错误。
* **未处理所有 IR 节点:**  未能为所有可能的 Go 语言结构生成相应的 SSA 代码。
* **忽略边界条件:**  例如，在处理切片或数组操作时，没有正确处理边界条件，可能导致生成的 SSA 代码存在潜在的运行时错误。
* **不正确的 `defer` 或 `go` 语句处理:**  在处理并发和延迟执行的语句时出现错误，导致程序行为不符合预期。
* **不正确的内联处理:**  在函数内联时，未能正确处理变量作用域和生命周期。

**功能归纳 (第 3 部分):**

这段代码（作为第 3 部分）主要负责 **将 Go 语言的控制流语句、赋值语句、基本数据类型的操作以及部分内置函数调用转换为 SSA 中间表示**。它构建了 SSA 图的基础结构，为后续的优化阶段提供了必要的信息。它特别关注于逻辑运算的短路求值、不同类型的赋值操作以及函数调用的各种场景。

请注意，这只是 `ssa.go` 文件的一部分，完整的 SSA 代码生成器会涉及更多的功能和更复杂的逻辑。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssagen/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共4部分，请归纳一下它的功能

"""
r.LogicalExpr)
		mid := s.f.NewBlock(ssa.BlockPlain)
		s.stmtList(cond.Init())
		s.condBranch(cond.X, mid, no, max(likely, 0))
		s.startBlock(mid)
		s.condBranch(cond.Y, yes, no, likely)
		return
		// Note: if likely==1, then both recursive calls pass 1.
		// If likely==-1, then we don't have enough information to decide
		// whether the first branch is likely or not. So we pass 0 for
		// the likeliness of the first branch.
		// TODO: have the frontend give us branch prediction hints for
		// OANDAND and OOROR nodes (if it ever has such info).
	case ir.OOROR:
		cond := cond.(*ir.LogicalExpr)
		mid := s.f.NewBlock(ssa.BlockPlain)
		s.stmtList(cond.Init())
		s.condBranch(cond.X, yes, mid, min(likely, 0))
		s.startBlock(mid)
		s.condBranch(cond.Y, yes, no, likely)
		return
		// Note: if likely==-1, then both recursive calls pass -1.
		// If likely==1, then we don't have enough info to decide
		// the likelihood of the first branch.
	case ir.ONOT:
		cond := cond.(*ir.UnaryExpr)
		s.stmtList(cond.Init())
		s.condBranch(cond.X, no, yes, -likely)
		return
	case ir.OCONVNOP:
		cond := cond.(*ir.ConvExpr)
		s.stmtList(cond.Init())
		s.condBranch(cond.X, yes, no, likely)
		return
	}
	c := s.expr(cond)
	b := s.endBlock()
	b.Kind = ssa.BlockIf
	b.SetControl(c)
	b.Likely = ssa.BranchPrediction(likely) // gc and ssa both use -1/0/+1 for likeliness
	b.AddEdgeTo(yes)
	b.AddEdgeTo(no)
}

type skipMask uint8

const (
	skipPtr skipMask = 1 << iota
	skipLen
	skipCap
)

// assign does left = right.
// Right has already been evaluated to ssa, left has not.
// If deref is true, then we do left = *right instead (and right has already been nil-checked).
// If deref is true and right == nil, just do left = 0.
// skip indicates assignments (at the top level) that can be avoided.
// mayOverlap indicates whether left&right might partially overlap in memory. Default is false.
func (s *state) assign(left ir.Node, right *ssa.Value, deref bool, skip skipMask) {
	s.assignWhichMayOverlap(left, right, deref, skip, false)
}
func (s *state) assignWhichMayOverlap(left ir.Node, right *ssa.Value, deref bool, skip skipMask, mayOverlap bool) {
	if left.Op() == ir.ONAME && ir.IsBlank(left) {
		return
	}
	t := left.Type()
	types.CalcSize(t)
	if s.canSSA(left) {
		if deref {
			s.Fatalf("can SSA LHS %v but not RHS %s", left, right)
		}
		if left.Op() == ir.ODOT {
			// We're assigning to a field of an ssa-able value.
			// We need to build a new structure with the new value for the
			// field we're assigning and the old values for the other fields.
			// For instance:
			//   type T struct {a, b, c int}
			//   var T x
			//   x.b = 5
			// For the x.b = 5 assignment we want to generate x = T{x.a, 5, x.c}

			// Grab information about the structure type.
			left := left.(*ir.SelectorExpr)
			t := left.X.Type()
			nf := t.NumFields()
			idx := fieldIdx(left)

			// Grab old value of structure.
			old := s.expr(left.X)

			// Make new structure.
			new := s.newValue0(ssa.OpStructMake, t)

			// Add fields as args.
			for i := 0; i < nf; i++ {
				if i == idx {
					new.AddArg(right)
				} else {
					new.AddArg(s.newValue1I(ssa.OpStructSelect, t.FieldType(i), int64(i), old))
				}
			}

			// Recursively assign the new value we've made to the base of the dot op.
			s.assign(left.X, new, false, 0)
			// TODO: do we need to update named values here?
			return
		}
		if left.Op() == ir.OINDEX && left.(*ir.IndexExpr).X.Type().IsArray() {
			left := left.(*ir.IndexExpr)
			s.pushLine(left.Pos())
			defer s.popLine()
			// We're assigning to an element of an ssa-able array.
			// a[i] = v
			t := left.X.Type()
			n := t.NumElem()

			i := s.expr(left.Index) // index
			if n == 0 {
				// The bounds check must fail.  Might as well
				// ignore the actual index and just use zeros.
				z := s.constInt(types.Types[types.TINT], 0)
				s.boundsCheck(z, z, ssa.BoundsIndex, false)
				return
			}
			if n != 1 {
				s.Fatalf("assigning to non-1-length array")
			}
			// Rewrite to a = [1]{v}
			len := s.constInt(types.Types[types.TINT], 1)
			s.boundsCheck(i, len, ssa.BoundsIndex, false) // checks i == 0
			v := s.newValue1(ssa.OpArrayMake1, t, right)
			s.assign(left.X, v, false, 0)
			return
		}
		left := left.(*ir.Name)
		// Update variable assignment.
		s.vars[left] = right
		s.addNamedValue(left, right)
		return
	}

	// If this assignment clobbers an entire local variable, then emit
	// OpVarDef so liveness analysis knows the variable is redefined.
	if base, ok := clobberBase(left).(*ir.Name); ok && base.OnStack() && skip == 0 && (t.HasPointers() || ssa.IsMergeCandidate(base)) {
		s.vars[memVar] = s.newValue1Apos(ssa.OpVarDef, types.TypeMem, base, s.mem(), !ir.IsAutoTmp(base))
	}

	// Left is not ssa-able. Compute its address.
	addr := s.addr(left)
	if ir.IsReflectHeaderDataField(left) {
		// Package unsafe's documentation says storing pointers into
		// reflect.SliceHeader and reflect.StringHeader's Data fields
		// is valid, even though they have type uintptr (#19168).
		// Mark it pointer type to signal the writebarrier pass to
		// insert a write barrier.
		t = types.Types[types.TUNSAFEPTR]
	}
	if deref {
		// Treat as a mem->mem move.
		if right == nil {
			s.zero(t, addr)
		} else {
			s.moveWhichMayOverlap(t, addr, right, mayOverlap)
		}
		return
	}
	// Treat as a store.
	s.storeType(t, addr, right, skip, !ir.IsAutoTmp(left))
}

// zeroVal returns the zero value for type t.
func (s *state) zeroVal(t *types.Type) *ssa.Value {
	switch {
	case t.IsInteger():
		switch t.Size() {
		case 1:
			return s.constInt8(t, 0)
		case 2:
			return s.constInt16(t, 0)
		case 4:
			return s.constInt32(t, 0)
		case 8:
			return s.constInt64(t, 0)
		default:
			s.Fatalf("bad sized integer type %v", t)
		}
	case t.IsFloat():
		switch t.Size() {
		case 4:
			return s.constFloat32(t, 0)
		case 8:
			return s.constFloat64(t, 0)
		default:
			s.Fatalf("bad sized float type %v", t)
		}
	case t.IsComplex():
		switch t.Size() {
		case 8:
			z := s.constFloat32(types.Types[types.TFLOAT32], 0)
			return s.entryNewValue2(ssa.OpComplexMake, t, z, z)
		case 16:
			z := s.constFloat64(types.Types[types.TFLOAT64], 0)
			return s.entryNewValue2(ssa.OpComplexMake, t, z, z)
		default:
			s.Fatalf("bad sized complex type %v", t)
		}

	case t.IsString():
		return s.constEmptyString(t)
	case t.IsPtrShaped():
		return s.constNil(t)
	case t.IsBoolean():
		return s.constBool(false)
	case t.IsInterface():
		return s.constInterface(t)
	case t.IsSlice():
		return s.constSlice(t)
	case t.IsStruct():
		n := t.NumFields()
		v := s.entryNewValue0(ssa.OpStructMake, t)
		for i := 0; i < n; i++ {
			v.AddArg(s.zeroVal(t.FieldType(i)))
		}
		return v
	case t.IsArray():
		switch t.NumElem() {
		case 0:
			return s.entryNewValue0(ssa.OpArrayMake0, t)
		case 1:
			return s.entryNewValue1(ssa.OpArrayMake1, t, s.zeroVal(t.Elem()))
		}
	}
	s.Fatalf("zero for type %v not implemented", t)
	return nil
}

type callKind int8

const (
	callNormal callKind = iota
	callDefer
	callDeferStack
	callGo
	callTail
)

type sfRtCallDef struct {
	rtfn  *obj.LSym
	rtype types.Kind
}

var softFloatOps map[ssa.Op]sfRtCallDef

func softfloatInit() {
	// Some of these operations get transformed by sfcall.
	softFloatOps = map[ssa.Op]sfRtCallDef{
		ssa.OpAdd32F: {typecheck.LookupRuntimeFunc("fadd32"), types.TFLOAT32},
		ssa.OpAdd64F: {typecheck.LookupRuntimeFunc("fadd64"), types.TFLOAT64},
		ssa.OpSub32F: {typecheck.LookupRuntimeFunc("fadd32"), types.TFLOAT32},
		ssa.OpSub64F: {typecheck.LookupRuntimeFunc("fadd64"), types.TFLOAT64},
		ssa.OpMul32F: {typecheck.LookupRuntimeFunc("fmul32"), types.TFLOAT32},
		ssa.OpMul64F: {typecheck.LookupRuntimeFunc("fmul64"), types.TFLOAT64},
		ssa.OpDiv32F: {typecheck.LookupRuntimeFunc("fdiv32"), types.TFLOAT32},
		ssa.OpDiv64F: {typecheck.LookupRuntimeFunc("fdiv64"), types.TFLOAT64},

		ssa.OpEq64F:   {typecheck.LookupRuntimeFunc("feq64"), types.TBOOL},
		ssa.OpEq32F:   {typecheck.LookupRuntimeFunc("feq32"), types.TBOOL},
		ssa.OpNeq64F:  {typecheck.LookupRuntimeFunc("feq64"), types.TBOOL},
		ssa.OpNeq32F:  {typecheck.LookupRuntimeFunc("feq32"), types.TBOOL},
		ssa.OpLess64F: {typecheck.LookupRuntimeFunc("fgt64"), types.TBOOL},
		ssa.OpLess32F: {typecheck.LookupRuntimeFunc("fgt32"), types.TBOOL},
		ssa.OpLeq64F:  {typecheck.LookupRuntimeFunc("fge64"), types.TBOOL},
		ssa.OpLeq32F:  {typecheck.LookupRuntimeFunc("fge32"), types.TBOOL},

		ssa.OpCvt32to32F:  {typecheck.LookupRuntimeFunc("fint32to32"), types.TFLOAT32},
		ssa.OpCvt32Fto32:  {typecheck.LookupRuntimeFunc("f32toint32"), types.TINT32},
		ssa.OpCvt64to32F:  {typecheck.LookupRuntimeFunc("fint64to32"), types.TFLOAT32},
		ssa.OpCvt32Fto64:  {typecheck.LookupRuntimeFunc("f32toint64"), types.TINT64},
		ssa.OpCvt64Uto32F: {typecheck.LookupRuntimeFunc("fuint64to32"), types.TFLOAT32},
		ssa.OpCvt32Fto64U: {typecheck.LookupRuntimeFunc("f32touint64"), types.TUINT64},
		ssa.OpCvt32to64F:  {typecheck.LookupRuntimeFunc("fint32to64"), types.TFLOAT64},
		ssa.OpCvt64Fto32:  {typecheck.LookupRuntimeFunc("f64toint32"), types.TINT32},
		ssa.OpCvt64to64F:  {typecheck.LookupRuntimeFunc("fint64to64"), types.TFLOAT64},
		ssa.OpCvt64Fto64:  {typecheck.LookupRuntimeFunc("f64toint64"), types.TINT64},
		ssa.OpCvt64Uto64F: {typecheck.LookupRuntimeFunc("fuint64to64"), types.TFLOAT64},
		ssa.OpCvt64Fto64U: {typecheck.LookupRuntimeFunc("f64touint64"), types.TUINT64},
		ssa.OpCvt32Fto64F: {typecheck.LookupRuntimeFunc("f32to64"), types.TFLOAT64},
		ssa.OpCvt64Fto32F: {typecheck.LookupRuntimeFunc("f64to32"), types.TFLOAT32},
	}
}

// TODO: do not emit sfcall if operation can be optimized to constant in later
// opt phase
func (s *state) sfcall(op ssa.Op, args ...*ssa.Value) (*ssa.Value, bool) {
	f2i := func(t *types.Type) *types.Type {
		switch t.Kind() {
		case types.TFLOAT32:
			return types.Types[types.TUINT32]
		case types.TFLOAT64:
			return types.Types[types.TUINT64]
		}
		return t
	}

	if callDef, ok := softFloatOps[op]; ok {
		switch op {
		case ssa.OpLess32F,
			ssa.OpLess64F,
			ssa.OpLeq32F,
			ssa.OpLeq64F:
			args[0], args[1] = args[1], args[0]
		case ssa.OpSub32F,
			ssa.OpSub64F:
			args[1] = s.newValue1(s.ssaOp(ir.ONEG, types.Types[callDef.rtype]), args[1].Type, args[1])
		}

		// runtime functions take uints for floats and returns uints.
		// Convert to uints so we use the right calling convention.
		for i, a := range args {
			if a.Type.IsFloat() {
				args[i] = s.newValue1(ssa.OpCopy, f2i(a.Type), a)
			}
		}

		rt := types.Types[callDef.rtype]
		result := s.rtcall(callDef.rtfn, true, []*types.Type{f2i(rt)}, args...)[0]
		if rt.IsFloat() {
			result = s.newValue1(ssa.OpCopy, rt, result)
		}
		if op == ssa.OpNeq32F || op == ssa.OpNeq64F {
			result = s.newValue1(ssa.OpNot, result.Type, result)
		}
		return result, true
	}
	return nil, false
}

// split breaks up a tuple-typed value into its 2 parts.
func (s *state) split(v *ssa.Value) (*ssa.Value, *ssa.Value) {
	p0 := s.newValue1(ssa.OpSelect0, v.Type.FieldType(0), v)
	p1 := s.newValue1(ssa.OpSelect1, v.Type.FieldType(1), v)
	return p0, p1
}

// intrinsicCall converts a call to a recognized intrinsic function into the intrinsic SSA operation.
func (s *state) intrinsicCall(n *ir.CallExpr) *ssa.Value {
	v := findIntrinsic(n.Fun.Sym())(s, n, s.intrinsicArgs(n))
	if ssa.IntrinsicsDebug > 0 {
		x := v
		if x == nil {
			x = s.mem()
		}
		if x.Op == ssa.OpSelect0 || x.Op == ssa.OpSelect1 {
			x = x.Args[0]
		}
		base.WarnfAt(n.Pos(), "intrinsic substitution for %v with %s", n.Fun.Sym().Name, x.LongString())
	}
	return v
}

// intrinsicArgs extracts args from n, evaluates them to SSA values, and returns them.
func (s *state) intrinsicArgs(n *ir.CallExpr) []*ssa.Value {
	args := make([]*ssa.Value, len(n.Args))
	for i, n := range n.Args {
		args[i] = s.expr(n)
	}
	return args
}

// openDeferRecord adds code to evaluate and store the function for an open-code defer
// call, and records info about the defer, so we can generate proper code on the
// exit paths. n is the sub-node of the defer node that is the actual function
// call. We will also record funcdata information on where the function is stored
// (as well as the deferBits variable), and this will enable us to run the proper
// defer calls during panics.
func (s *state) openDeferRecord(n *ir.CallExpr) {
	if len(n.Args) != 0 || n.Op() != ir.OCALLFUNC || n.Fun.Type().NumResults() != 0 {
		s.Fatalf("defer call with arguments or results: %v", n)
	}

	opendefer := &openDeferInfo{
		n: n,
	}
	fn := n.Fun
	// We must always store the function value in a stack slot for the
	// runtime panic code to use. But in the defer exit code, we will
	// call the function directly if it is a static function.
	closureVal := s.expr(fn)
	closure := s.openDeferSave(fn.Type(), closureVal)
	opendefer.closureNode = closure.Aux.(*ir.Name)
	if !(fn.Op() == ir.ONAME && fn.(*ir.Name).Class == ir.PFUNC) {
		opendefer.closure = closure
	}
	index := len(s.openDefers)
	s.openDefers = append(s.openDefers, opendefer)

	// Update deferBits only after evaluation and storage to stack of
	// the function is successful.
	bitvalue := s.constInt8(types.Types[types.TUINT8], 1<<uint(index))
	newDeferBits := s.newValue2(ssa.OpOr8, types.Types[types.TUINT8], s.variable(deferBitsVar, types.Types[types.TUINT8]), bitvalue)
	s.vars[deferBitsVar] = newDeferBits
	s.store(types.Types[types.TUINT8], s.deferBitsAddr, newDeferBits)
}

// openDeferSave generates SSA nodes to store a value (with type t) for an
// open-coded defer at an explicit autotmp location on the stack, so it can be
// reloaded and used for the appropriate call on exit. Type t must be a function type
// (therefore SSAable). val is the value to be stored. The function returns an SSA
// value representing a pointer to the autotmp location.
func (s *state) openDeferSave(t *types.Type, val *ssa.Value) *ssa.Value {
	if !ssa.CanSSA(t) {
		s.Fatalf("openDeferSave of non-SSA-able type %v val=%v", t, val)
	}
	if !t.HasPointers() {
		s.Fatalf("openDeferSave of pointerless type %v val=%v", t, val)
	}
	pos := val.Pos
	temp := typecheck.TempAt(pos.WithNotStmt(), s.curfn, t)
	temp.SetOpenDeferSlot(true)
	temp.SetFrameOffset(int64(len(s.openDefers))) // so cmpstackvarlt can order them
	var addrTemp *ssa.Value
	// Use OpVarLive to make sure stack slot for the closure is not removed by
	// dead-store elimination
	if s.curBlock.ID != s.f.Entry.ID {
		// Force the tmp storing this defer function to be declared in the entry
		// block, so that it will be live for the defer exit code (which will
		// actually access it only if the associated defer call has been activated).
		if t.HasPointers() {
			s.defvars[s.f.Entry.ID][memVar] = s.f.Entry.NewValue1A(src.NoXPos, ssa.OpVarDef, types.TypeMem, temp, s.defvars[s.f.Entry.ID][memVar])
		}
		s.defvars[s.f.Entry.ID][memVar] = s.f.Entry.NewValue1A(src.NoXPos, ssa.OpVarLive, types.TypeMem, temp, s.defvars[s.f.Entry.ID][memVar])
		addrTemp = s.f.Entry.NewValue2A(src.NoXPos, ssa.OpLocalAddr, types.NewPtr(temp.Type()), temp, s.sp, s.defvars[s.f.Entry.ID][memVar])
	} else {
		// Special case if we're still in the entry block. We can't use
		// the above code, since s.defvars[s.f.Entry.ID] isn't defined
		// until we end the entry block with s.endBlock().
		if t.HasPointers() {
			s.vars[memVar] = s.newValue1Apos(ssa.OpVarDef, types.TypeMem, temp, s.mem(), false)
		}
		s.vars[memVar] = s.newValue1Apos(ssa.OpVarLive, types.TypeMem, temp, s.mem(), false)
		addrTemp = s.newValue2Apos(ssa.OpLocalAddr, types.NewPtr(temp.Type()), temp, s.sp, s.mem(), false)
	}
	// Since we may use this temp during exit depending on the
	// deferBits, we must define it unconditionally on entry.
	// Therefore, we must make sure it is zeroed out in the entry
	// block if it contains pointers, else GC may wrongly follow an
	// uninitialized pointer value.
	temp.SetNeedzero(true)
	// We are storing to the stack, hence we can avoid the full checks in
	// storeType() (no write barrier) and do a simple store().
	s.store(t, addrTemp, val)
	return addrTemp
}

// openDeferExit generates SSA for processing all the open coded defers at exit.
// The code involves loading deferBits, and checking each of the bits to see if
// the corresponding defer statement was executed. For each bit that is turned
// on, the associated defer call is made.
func (s *state) openDeferExit() {
	deferExit := s.f.NewBlock(ssa.BlockPlain)
	s.endBlock().AddEdgeTo(deferExit)
	s.startBlock(deferExit)
	s.lastDeferExit = deferExit
	s.lastDeferCount = len(s.openDefers)
	zeroval := s.constInt8(types.Types[types.TUINT8], 0)
	// Test for and run defers in reverse order
	for i := len(s.openDefers) - 1; i >= 0; i-- {
		r := s.openDefers[i]
		bCond := s.f.NewBlock(ssa.BlockPlain)
		bEnd := s.f.NewBlock(ssa.BlockPlain)

		deferBits := s.variable(deferBitsVar, types.Types[types.TUINT8])
		// Generate code to check if the bit associated with the current
		// defer is set.
		bitval := s.constInt8(types.Types[types.TUINT8], 1<<uint(i))
		andval := s.newValue2(ssa.OpAnd8, types.Types[types.TUINT8], deferBits, bitval)
		eqVal := s.newValue2(ssa.OpEq8, types.Types[types.TBOOL], andval, zeroval)
		b := s.endBlock()
		b.Kind = ssa.BlockIf
		b.SetControl(eqVal)
		b.AddEdgeTo(bEnd)
		b.AddEdgeTo(bCond)
		bCond.AddEdgeTo(bEnd)
		s.startBlock(bCond)

		// Clear this bit in deferBits and force store back to stack, so
		// we will not try to re-run this defer call if this defer call panics.
		nbitval := s.newValue1(ssa.OpCom8, types.Types[types.TUINT8], bitval)
		maskedval := s.newValue2(ssa.OpAnd8, types.Types[types.TUINT8], deferBits, nbitval)
		s.store(types.Types[types.TUINT8], s.deferBitsAddr, maskedval)
		// Use this value for following tests, so we keep previous
		// bits cleared.
		s.vars[deferBitsVar] = maskedval

		// Generate code to call the function call of the defer, using the
		// closure that were stored in argtmps at the point of the defer
		// statement.
		fn := r.n.Fun
		stksize := fn.Type().ArgWidth()
		var callArgs []*ssa.Value
		var call *ssa.Value
		if r.closure != nil {
			v := s.load(r.closure.Type.Elem(), r.closure)
			s.maybeNilCheckClosure(v, callDefer)
			codeptr := s.rawLoad(types.Types[types.TUINTPTR], v)
			aux := ssa.ClosureAuxCall(s.f.ABIDefault.ABIAnalyzeTypes(nil, nil))
			call = s.newValue2A(ssa.OpClosureLECall, aux.LateExpansionResultType(), aux, codeptr, v)
		} else {
			aux := ssa.StaticAuxCall(fn.(*ir.Name).Linksym(), s.f.ABIDefault.ABIAnalyzeTypes(nil, nil))
			call = s.newValue0A(ssa.OpStaticLECall, aux.LateExpansionResultType(), aux)
		}
		callArgs = append(callArgs, s.mem())
		call.AddArgs(callArgs...)
		call.AuxInt = stksize
		s.vars[memVar] = s.newValue1I(ssa.OpSelectN, types.TypeMem, 0, call)
		// Make sure that the stack slots with pointers are kept live
		// through the call (which is a pre-emption point). Also, we will
		// use the first call of the last defer exit to compute liveness
		// for the deferreturn, so we want all stack slots to be live.
		if r.closureNode != nil {
			s.vars[memVar] = s.newValue1Apos(ssa.OpVarLive, types.TypeMem, r.closureNode, s.mem(), false)
		}

		s.endBlock()
		s.startBlock(bEnd)
	}
}

func (s *state) callResult(n *ir.CallExpr, k callKind) *ssa.Value {
	return s.call(n, k, false, nil)
}

func (s *state) callAddr(n *ir.CallExpr, k callKind) *ssa.Value {
	return s.call(n, k, true, nil)
}

// Calls the function n using the specified call type.
// Returns the address of the return value (or nil if none).
func (s *state) call(n *ir.CallExpr, k callKind, returnResultAddr bool, deferExtra ir.Expr) *ssa.Value {
	s.prevCall = nil
	var calleeLSym *obj.LSym // target function (if static)
	var closure *ssa.Value   // ptr to closure to run (if dynamic)
	var codeptr *ssa.Value   // ptr to target code (if dynamic)
	var dextra *ssa.Value    // defer extra arg
	var rcvr *ssa.Value      // receiver to set
	fn := n.Fun
	var ACArgs []*types.Type    // AuxCall args
	var ACResults []*types.Type // AuxCall results
	var callArgs []*ssa.Value   // For late-expansion, the args themselves (not stored, args to the call instead).

	callABI := s.f.ABIDefault

	if k != callNormal && k != callTail && (len(n.Args) != 0 || n.Op() == ir.OCALLINTER || n.Fun.Type().NumResults() != 0) {
		s.Fatalf("go/defer call with arguments: %v", n)
	}

	switch n.Op() {
	case ir.OCALLFUNC:
		if (k == callNormal || k == callTail) && fn.Op() == ir.ONAME && fn.(*ir.Name).Class == ir.PFUNC {
			fn := fn.(*ir.Name)
			calleeLSym = callTargetLSym(fn)
			if buildcfg.Experiment.RegabiArgs {
				// This is a static call, so it may be
				// a direct call to a non-ABIInternal
				// function. fn.Func may be nil for
				// some compiler-generated functions,
				// but those are all ABIInternal.
				if fn.Func != nil {
					callABI = abiForFunc(fn.Func, s.f.ABI0, s.f.ABI1)
				}
			} else {
				// TODO(register args) remove after register abi is working
				inRegistersImported := fn.Pragma()&ir.RegisterParams != 0
				inRegistersSamePackage := fn.Func != nil && fn.Func.Pragma&ir.RegisterParams != 0
				if inRegistersImported || inRegistersSamePackage {
					callABI = s.f.ABI1
				}
			}
			break
		}
		closure = s.expr(fn)
		if k != callDefer && k != callDeferStack {
			// Deferred nil function needs to panic when the function is invoked,
			// not the point of defer statement.
			s.maybeNilCheckClosure(closure, k)
		}
	case ir.OCALLINTER:
		if fn.Op() != ir.ODOTINTER {
			s.Fatalf("OCALLINTER: n.Left not an ODOTINTER: %v", fn.Op())
		}
		fn := fn.(*ir.SelectorExpr)
		var iclosure *ssa.Value
		iclosure, rcvr = s.getClosureAndRcvr(fn)
		if k == callNormal {
			codeptr = s.load(types.Types[types.TUINTPTR], iclosure)
		} else {
			closure = iclosure
		}
	}
	if deferExtra != nil {
		dextra = s.expr(deferExtra)
	}

	params := callABI.ABIAnalyze(n.Fun.Type(), false /* Do not set (register) nNames from caller side -- can cause races. */)
	types.CalcSize(fn.Type())
	stksize := params.ArgWidth() // includes receiver, args, and results

	res := n.Fun.Type().Results()
	if k == callNormal || k == callTail {
		for _, p := range params.OutParams() {
			ACResults = append(ACResults, p.Type)
		}
	}

	var call *ssa.Value
	if k == callDeferStack {
		if stksize != 0 {
			s.Fatalf("deferprocStack with non-zero stack size %d: %v", stksize, n)
		}
		// Make a defer struct on the stack.
		t := deferstruct()
		n, addr := s.temp(n.Pos(), t)
		n.SetNonMergeable(true)
		s.store(closure.Type,
			s.newValue1I(ssa.OpOffPtr, closure.Type.PtrTo(), t.FieldOff(deferStructFnField), addr),
			closure)

		// Call runtime.deferprocStack with pointer to _defer record.
		ACArgs = append(ACArgs, types.Types[types.TUINTPTR])
		aux := ssa.StaticAuxCall(ir.Syms.DeferprocStack, s.f.ABIDefault.ABIAnalyzeTypes(ACArgs, ACResults))
		callArgs = append(callArgs, addr, s.mem())
		call = s.newValue0A(ssa.OpStaticLECall, aux.LateExpansionResultType(), aux)
		call.AddArgs(callArgs...)
		call.AuxInt = int64(types.PtrSize) // deferprocStack takes a *_defer arg
	} else {
		// Store arguments to stack, including defer/go arguments and receiver for method calls.
		// These are written in SP-offset order.
		argStart := base.Ctxt.Arch.FixedFrameSize
		// Defer/go args.
		if k != callNormal && k != callTail {
			// Write closure (arg to newproc/deferproc).
			ACArgs = append(ACArgs, types.Types[types.TUINTPTR]) // not argExtra
			callArgs = append(callArgs, closure)
			stksize += int64(types.PtrSize)
			argStart += int64(types.PtrSize)
			if dextra != nil {
				// Extra token of type any for deferproc
				ACArgs = append(ACArgs, types.Types[types.TINTER])
				callArgs = append(callArgs, dextra)
				stksize += 2 * int64(types.PtrSize)
				argStart += 2 * int64(types.PtrSize)
			}
		}

		// Set receiver (for interface calls).
		if rcvr != nil {
			callArgs = append(callArgs, rcvr)
		}

		// Write args.
		t := n.Fun.Type()
		args := n.Args

		for _, p := range params.InParams() { // includes receiver for interface calls
			ACArgs = append(ACArgs, p.Type)
		}

		// Split the entry block if there are open defers, because later calls to
		// openDeferSave may cause a mismatch between the mem for an OpDereference
		// and the call site which uses it. See #49282.
		if s.curBlock.ID == s.f.Entry.ID && s.hasOpenDefers {
			b := s.endBlock()
			b.Kind = ssa.BlockPlain
			curb := s.f.NewBlock(ssa.BlockPlain)
			b.AddEdgeTo(curb)
			s.startBlock(curb)
		}

		for i, n := range args {
			callArgs = append(callArgs, s.putArg(n, t.Param(i).Type))
		}

		callArgs = append(callArgs, s.mem())

		// call target
		switch {
		case k == callDefer:
			sym := ir.Syms.Deferproc
			if dextra != nil {
				sym = ir.Syms.Deferprocat
			}
			aux := ssa.StaticAuxCall(sym, s.f.ABIDefault.ABIAnalyzeTypes(ACArgs, ACResults)) // TODO paramResultInfo for Deferproc(at)
			call = s.newValue0A(ssa.OpStaticLECall, aux.LateExpansionResultType(), aux)
		case k == callGo:
			aux := ssa.StaticAuxCall(ir.Syms.Newproc, s.f.ABIDefault.ABIAnalyzeTypes(ACArgs, ACResults))
			call = s.newValue0A(ssa.OpStaticLECall, aux.LateExpansionResultType(), aux) // TODO paramResultInfo for Newproc
		case closure != nil:
			// rawLoad because loading the code pointer from a
			// closure is always safe, but IsSanitizerSafeAddr
			// can't always figure that out currently, and it's
			// critical that we not clobber any arguments already
			// stored onto the stack.
			codeptr = s.rawLoad(types.Types[types.TUINTPTR], closure)
			aux := ssa.ClosureAuxCall(callABI.ABIAnalyzeTypes(ACArgs, ACResults))
			call = s.newValue2A(ssa.OpClosureLECall, aux.LateExpansionResultType(), aux, codeptr, closure)
		case codeptr != nil:
			// Note that the "receiver" parameter is nil because the actual receiver is the first input parameter.
			aux := ssa.InterfaceAuxCall(params)
			call = s.newValue1A(ssa.OpInterLECall, aux.LateExpansionResultType(), aux, codeptr)
		case calleeLSym != nil:
			aux := ssa.StaticAuxCall(calleeLSym, params)
			call = s.newValue0A(ssa.OpStaticLECall, aux.LateExpansionResultType(), aux)
			if k == callTail {
				call.Op = ssa.OpTailLECall
				stksize = 0 // Tail call does not use stack. We reuse caller's frame.
			}
		default:
			s.Fatalf("bad call type %v %v", n.Op(), n)
		}
		call.AddArgs(callArgs...)
		call.AuxInt = stksize // Call operations carry the argsize of the callee along with them
	}
	s.prevCall = call
	s.vars[memVar] = s.newValue1I(ssa.OpSelectN, types.TypeMem, int64(len(ACResults)), call)
	// Insert VarLive opcodes.
	for _, v := range n.KeepAlive {
		if !v.Addrtaken() {
			s.Fatalf("KeepAlive variable %v must have Addrtaken set", v)
		}
		switch v.Class {
		case ir.PAUTO, ir.PPARAM, ir.PPARAMOUT:
		default:
			s.Fatalf("KeepAlive variable %v must be Auto or Arg", v)
		}
		s.vars[memVar] = s.newValue1A(ssa.OpVarLive, types.TypeMem, v, s.mem())
	}

	// Finish block for defers
	if k == callDefer || k == callDeferStack {
		b := s.endBlock()
		b.Kind = ssa.BlockDefer
		b.SetControl(call)
		bNext := s.f.NewBlock(ssa.BlockPlain)
		b.AddEdgeTo(bNext)
		// Add recover edge to exit code.
		r := s.f.NewBlock(ssa.BlockPlain)
		s.startBlock(r)
		s.exit()
		b.AddEdgeTo(r)
		b.Likely = ssa.BranchLikely
		s.startBlock(bNext)
	}

	if len(res) == 0 || k != callNormal {
		// call has no return value. Continue with the next statement.
		return nil
	}
	fp := res[0]
	if returnResultAddr {
		return s.resultAddrOfCall(call, 0, fp.Type)
	}
	return s.newValue1I(ssa.OpSelectN, fp.Type, 0, call)
}

// maybeNilCheckClosure checks if a nil check of a closure is needed in some
// architecture-dependent situations and, if so, emits the nil check.
func (s *state) maybeNilCheckClosure(closure *ssa.Value, k callKind) {
	if Arch.LinkArch.Family == sys.Wasm || buildcfg.GOOS == "aix" && k != callGo {
		// On AIX, the closure needs to be verified as fn can be nil, except if it's a call go. This needs to be handled by the runtime to have the "go of nil func value" error.
		// TODO(neelance): On other architectures this should be eliminated by the optimization steps
		s.nilCheck(closure)
	}
}

// getClosureAndRcvr returns values for the appropriate closure and receiver of an
// interface call
func (s *state) getClosureAndRcvr(fn *ir.SelectorExpr) (*ssa.Value, *ssa.Value) {
	i := s.expr(fn.X)
	itab := s.newValue1(ssa.OpITab, types.Types[types.TUINTPTR], i)
	s.nilCheck(itab)
	itabidx := fn.Offset() + rttype.ITab.OffsetOf("Fun")
	closure := s.newValue1I(ssa.OpOffPtr, s.f.Config.Types.UintptrPtr, itabidx, itab)
	rcvr := s.newValue1(ssa.OpIData, s.f.Config.Types.BytePtr, i)
	return closure, rcvr
}

// etypesign returns the signed-ness of e, for integer/pointer etypes.
// -1 means signed, +1 means unsigned, 0 means non-integer/non-pointer.
func etypesign(e types.Kind) int8 {
	switch e {
	case types.TINT8, types.TINT16, types.TINT32, types.TINT64, types.TINT:
		return -1
	case types.TUINT8, types.TUINT16, types.TUINT32, types.TUINT64, types.TUINT, types.TUINTPTR, types.TUNSAFEPTR:
		return +1
	}
	return 0
}

// addr converts the address of the expression n to SSA, adds it to s and returns the SSA result.
// The value that the returned Value represents is guaranteed to be non-nil.
func (s *state) addr(n ir.Node) *ssa.Value {
	if n.Op() != ir.ONAME {
		s.pushLine(n.Pos())
		defer s.popLine()
	}

	if s.canSSA(n) {
		s.Fatalf("addr of canSSA expression: %+v", n)
	}

	t := types.NewPtr(n.Type())
	linksymOffset := func(lsym *obj.LSym, offset int64) *ssa.Value {
		v := s.entryNewValue1A(ssa.OpAddr, t, lsym, s.sb)
		// TODO: Make OpAddr use AuxInt as well as Aux.
		if offset != 0 {
			v = s.entryNewValue1I(ssa.OpOffPtr, v.Type, offset, v)
		}
		return v
	}
	switch n.Op() {
	case ir.OLINKSYMOFFSET:
		no := n.(*ir.LinksymOffsetExpr)
		return linksymOffset(no.Linksym, no.Offset_)
	case ir.ONAME:
		n := n.(*ir.Name)
		if n.Heapaddr != nil {
			return s.expr(n.Heapaddr)
		}
		switch n.Class {
		case ir.PEXTERN:
			// global variable
			return linksymOffset(n.Linksym(), 0)
		case ir.PPARAM:
			// parameter slot
			v := s.decladdrs[n]
			if v != nil {
				return v
			}
			s.Fatalf("addr of undeclared ONAME %v. declared: %v", n, s.decladdrs)
			return nil
		case ir.PAUTO:
			return s.newValue2Apos(ssa.OpLocalAddr, t, n, s.sp, s.mem(), !ir.IsAutoTmp(n))

		case ir.PPARAMOUT: // Same as PAUTO -- cannot generate LEA early.
			// ensure that we reuse symbols for out parameters so
			// that cse works on their addresses
			return s.newValue2Apos(ssa.OpLocalAddr, t, n, s.sp, s.mem(), true)
		default:
			s.Fatalf("variable address class %v not implemented", n.Class)
			return nil
		}
	case ir.ORESULT:
		// load return from callee
		n := n.(*ir.ResultExpr)
		return s.resultAddrOfCall(s.prevCall, n.Index, n.Type())
	case ir.OINDEX:
		n := n.(*ir.IndexExpr)
		if n.X.Type().IsSlice() {
			a := s.expr(n.X)
			i := s.expr(n.Index)
			len := s.newValue1(ssa.OpSliceLen, types.Types[types.TINT], a)
			i = s.boundsCheck(i, len, ssa.BoundsIndex, n.Bounded())
			p := s.newValue1(ssa.OpSlicePtr, t, a)
			return s.newValue2(ssa.OpPtrIndex, t, p, i)
		} else { // array
			a := s.addr(n.X)
			i := s.expr(n.Index)
			len := s.constInt(types.Types[types.TINT], n.X.Type().NumElem())
			i = s.boundsCheck(i, len, ssa.BoundsIndex, n.Bounded())
			return s.newValue2(ssa.OpPtrIndex, types.NewPtr(n.X.Type().Elem()), a, i)
		}
	case ir.ODEREF:
		n := n.(*ir.StarExpr)
		return s.exprPtr(n.X, n.Bounded(), n.Pos())
	case ir.ODOT:
		n := n.(*ir.SelectorExpr)
		p := s.addr(n.X)
		return s.newValue1I(ssa.OpOffPtr, t, n.Offset(), p)
	case ir.ODOTPTR:
		n := n.(*ir.SelectorExpr)
		p := s.exprPtr(n.X, n.Bounded(), n.Pos())
		return s.newValue1I(ssa.OpOffPtr, t, n.Offset(), p)
	case ir.OCONVNOP:
		n := n.(*ir.ConvExpr)
		if n.Type() == n.X.Type() {
			return s.addr(n.X)
		}
		addr := s.addr(n.X)
		return s.newValue1(ssa.OpCopy, t, addr) // ensure that addr has the right type
	case ir.OCALLFUNC, ir.OCALLINTER:
		n := n.(*ir.CallExpr)
		return s.callAddr(n, callNormal)
	case ir.ODOTTYPE, ir.ODYNAMICDOTTYPE:
		var v *ssa.Value
		if n.Op() == ir.ODOTTYPE {
			v, _ = s.dottype(n.(*ir.TypeAssertExpr), false)
		} else {
			v, _ = s.dynamicDottype(n.(*ir.DynamicTypeAssertExpr), false)
		}
		if v.Op != ssa.OpLoad {
			s.Fatalf("dottype of non-load")
		}
		if v.Args[1] != s.mem() {
			s.Fatalf("memory no longer live from dottype load")
		}
		return v.Args[0]
	default:
		s.Fatalf("unhandled addr %v", n.Op())
		return nil
	}
}

// canSSA reports whether n is SSA-able.
// n must be an ONAME (or an ODOT sequence with an ONAME base).
func (s *state) canSSA(n ir.Node) bool {
	if base.Flag.N != 0 {
		return false
	}
	for {
		nn := n
		if nn.Op() == ir.ODOT {
			nn := nn.(*ir.SelectorExpr)
			n = nn.X
			continue
		}
		if nn.Op() == ir.OINDEX {
			nn := nn.(*ir.IndexExpr)
			if nn.X.Type().IsArray() {
				n = nn.X
				continue
			}
		}
		break
	}
	if n.Op() != ir.ONAME {
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
"""




```