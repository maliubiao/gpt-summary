Response:
My goal is to analyze the provided Go code snippet and extract its functionalities, infer its purpose within the larger `go/src/cmd/compile/internal/ssagen/ssa.go` file, and provide illustrative examples. Since this is part 5 of 8, I also need to summarize the functionality covered in this specific part.

Here's a breakdown of the thinking process to arrive at the answer:

1. **Identify Key Functions and Data Structures:** The first step is to scan the code for function definitions and type definitions. This immediately highlights `condBranch`, `assign`, `assignWhichMayOverlap`, `zeroVal`, `sfcall`, `split`, `intrinsicCall`, `intrinsicArgs`, `openDeferRecord`, `openDeferSave`, `openDeferExit`, `call`, `callResult`, `callAddr`, `maybeNilCheckClosure`, `getClosureAndRcvr`, `etypesign`, and `addr`. The `skipMask` enum and `softFloatOps` map also stand out.

2. **Analyze Individual Function Functionality:**  For each identified function, carefully read its code and comments to understand its purpose.

    * **`condBranch`**:  This function clearly handles conditional branching based on different logical expressions (AND, OR, NOT, etc.). The `likely` parameter suggests it deals with branch prediction hints.

    * **`assign` and `assignWhichMayOverlap`**: These functions handle assignment operations (`left = right`). The `deref` parameter indicates handling pointer dereferences, and `skip` suggests optimizing certain assignments. The `mayOverlap` parameter deals with potential memory overlap.

    * **`zeroVal`**:  This function is straightforward - it returns the zero value for a given Go type.

    * **`sfcall`**: This seems to handle calls to "soft-float" runtime functions, possibly for architectures without native floating-point support. It involves converting float arguments to integers and handling return values.

    * **`split`**:  This function splits a tuple (pair) of values, likely related to function returns.

    * **`intrinsicCall` and `intrinsicArgs`**: These deal with "intrinsic" function calls, which are special functions that can be optimized directly into SSA operations.

    * **`openDeferRecord`**: This function appears to record information about `defer` statements that are implemented "open-coded" (directly in the SSA).

    * **`openDeferSave`**:  This function saves the function value of an open-coded `defer` onto the stack.

    * **`openDeferExit`**: This function generates the SSA code to execute the open-coded `defer` statements when a function exits.

    * **`call`, `callResult`, `callAddr`**: These functions handle different kinds of function calls, including normal calls, calls that return the address of the result, `defer` calls, and `go` calls. They manage argument passing and result retrieval.

    * **`maybeNilCheckClosure`**:  This function handles nil checks for function closures, potentially depending on the target architecture.

    * **`getClosureAndRcvr`**: This function extracts the closure and receiver for interface method calls.

    * **`etypesign`**: This is a utility function to determine the signedness of an integer type.

    * **`addr`**: This function calculates the address of a given expression, handling different kinds of variables, array/slice indexing, dereferences, and field accesses.

3. **Infer Higher-Level Functionality and Context:** Based on the individual function analyses, I can start to infer the broader purpose of this code:

    * **SSA Generation for Control Flow and Assignments:**  `condBranch`, `assign`, and `addr` are fundamental to translating Go's control flow statements and assignments into the SSA form.

    * **Handling Special Function Calls:** `sfcall` and `intrinsicCall` indicate handling of specific kinds of function calls in a specialized way.

    * **Implementing `defer` and `go` Statements:** The `openDefer*` functions and the `call` function's handling of `callDefer` and `callGo` clearly point to the implementation of these Go features.

    * **Function Call Conventions:** The `call` function and its related helpers deal with the details of how arguments are passed and return values are retrieved during function calls.

    * **Memory Management (Implicit):**  While not explicitly a memory management module, the handling of addresses and assignments is crucial for how the SSA represents memory operations.

4. **Provide Illustrative Go Code Examples:**  For the key functionalities, create simple Go code snippets that would trigger the execution of the analyzed code. This helps to solidify the understanding and demonstrate the code's purpose.

5. **Address Potential User Errors (If Applicable):**  Consider any common pitfalls or misunderstandings a user might have when dealing with the Go features implemented by this code. In this case, the complexity of `defer` behavior and the subtle differences between open-coded and runtime `defer` implementations could be points of confusion.

6. **Summarize the Functionality of this Part:** Based on the analysis, synthesize a concise summary of the functionalities covered in this specific part of the `ssa.go` file. Emphasize the key areas like control flow, assignments, special calls, and the implementation of `defer` and `go`.

7. **Structure the Answer:** Organize the findings logically, using headings and bullet points to improve readability. Use code blocks for Go examples and maintain a consistent tone. Ensure all parts of the prompt are addressed.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps `sfcall` is about cross-compilation. **Correction:** The comments indicate it's for architectures without native floating-point, which is a more specific purpose.
* **Initial thought:** The `openDefer*` functions are about all `defer` implementations. **Correction:**  The "open-coded" prefix suggests it's a specific optimization or implementation strategy for `defer`.
* **Ensuring Go examples are minimal and focused:**  Avoid overly complex examples that might obscure the specific functionality being demonstrated.
* **Double-checking the prompt requirements:**  Make sure all requested information (functionalities, Go examples, assumptions, command-line arguments (if any), potential errors, and summary) is included. The prompt specifically asked for the summary of *this* part, so focus on the functionalities present in the provided snippet.

By following these steps, the comprehensive and informative answer can be generated.
这是 `go/src/cmd/compile/internal/ssagen/ssa.go` 文件的第 5 部分，主要负责将 Go 语言的**控制流结构**（如条件语句）和**赋值语句**转换成静态单赋值（SSA）形式的中间表示。

以下是这一部分代码的主要功能归纳：

**1. 条件分支 (`condBranch`)**:

*   根据不同的布尔表达式 (`ir.Node`) 生成条件分支的 SSA 代码。
*   支持 `AND` (`ir.OANDAND`)、`OR` (`ir.OOROR`)、`NOT` (`ir.ONOT`) 和类型转换 (`ir.OCONVNOP`) 等逻辑运算。
*   允许传递 `likely` 参数来指示分支预测信息，优化代码执行。

**2. 赋值 (`assign`, `assignWhichMayOverlap`)**:

*   将 Go 语言的赋值语句 (`left = right`) 转换为 SSA 指令。
*   `right` 已经被求值为 SSA 值，`left` 尚未求值。
*   支持解引用赋值 (`left = *right`)。
*   `skip` 参数用于指示可以避免的赋值（例如，在结构体或数组赋值中，某些字段或元素可能不需要赋值）。
*   `mayOverlap` 参数指示左右两边的内存区域可能存在重叠，需要特殊处理以避免数据损坏。
*   处理赋值给 SSAable 的左值（例如，局部变量）和非 SSAable 的左值（需要计算地址）。
*   特殊处理结构体字段赋值，生成新的结构体值。
*   特殊处理数组元素赋值。
*   在赋值给局部变量时，可能会发出 `OpVarDef` 指令，以便进行活跃性分析。

**3. 获取零值 (`zeroVal`)**:

*   返回给定类型 (`*types.Type`) 的零值的 SSA 表示。
*   支持各种基本类型，如整型、浮点型、复数、字符串、指针、布尔值、接口、切片、结构体和数组。

**4. 软浮点调用 (`sfcall`)**:

*   处理一些无法直接映射到硬件指令的浮点运算，将其转换为对运行时函数的调用。
*   维护一个 `softFloatOps` 映射，存储了需要软浮点处理的 SSA 操作符以及对应的运行时函数。
*   在调用运行时函数之前，可能需要进行类型转换。

**5. 拆分元组 (`split`)**:

*   将一个元组类型的 SSA 值拆分成它的两个组成部分。这通常用于处理返回多个值的函数。

**6. 内联函数调用 (`intrinsicCall`, `intrinsicArgs`)**:

*   尝试将某些特定的函数调用（称为 "intrinsic" 函数）替换为更底层的 SSA 操作，以提高性能。
*   `intrinsicCall` 查找并执行内联替换。
*   `intrinsicArgs` 提取函数调用的参数并将其转换为 SSA 值。

**7. 开放编码的 defer 记录和退出处理 (`openDeferRecord`, `openDeferSave`, `openDeferExit`)**:

*   处理使用 "开放编码" 方式实现的 `defer` 语句（一种优化手段）。
*   `openDeferRecord` 记录 `defer` 调用的相关信息，并将函数值存储到栈上。
*   `openDeferSave` 生成 SSA 代码来保存 `defer` 调用的函数值到一个临时的栈位置。
*   `openDeferExit` 生成在函数退出时执行所有已注册的开放编码 `defer` 调用的 SSA 代码。它会检查一个 `deferBits` 变量来确定哪些 `defer` 语句被执行过。

**8. 函数调用 (`call`, `callResult`, `callAddr`)**:

*   处理各种类型的函数调用，包括普通调用、`defer` 调用和 `go` 协程启动。
*   `call` 是核心函数，负责生成函数调用的 SSA 代码，包括设置参数、调用目标函数、处理返回值等。
*   `callResult` 返回函数调用的返回值。
*   `callAddr` 返回函数调用返回值的地址。
*   根据调用类型 (`callKind`) 和目标函数的特性，选择合适的 SSA 指令。
*   处理接口方法调用，需要获取接口的元数据（itab）和数据指针。

**9. 可选的空指针检查 (`maybeNilCheckClosure`)**:

*   根据目标架构，在某些情况下对函数闭包进行空指针检查。

**10. 获取闭包和接收者 (`getClosureAndRcvr`)**:

*   对于接口方法调用，提取接口的闭包指针和接收者。

**11. 获取类型的符号 (`etypesign`)**:

*   判断给定的类型是带符号的、无符号的还是非整数/指针类型。

**12. 获取地址 (`addr`)**:

*   计算并返回给定表达式 (`ir.Node`) 的地址的 SSA 表示。
*   支持获取各种类型表达式的地址，例如局部变量、全局变量、参数、数组元素、切片元素、结构体字段、指针解引用、函数调用返回值等。
*   对于 SSAable 的表达式，会报错。

**推断 Go 语言功能的实现 (部分):**

这一部分代码主要涉及以下 Go 语言功能的 SSA 代码生成：

*   **条件语句 (`if`, `else`)**: `condBranch` 函数是实现 `if` 语句和相关控制流的关键。
*   **赋值语句**: `assign` 和相关函数处理各种赋值操作。
*   **基本类型的零值**: `zeroVal` 用于初始化变量或结构体字段。
*   **函数调用**: `call` 系列函数处理各种函数调用方式。
*   **`defer` 语句 (特定优化)**: `openDeferRecord`, `openDeferSave`, `openDeferExit` 实现了 `defer` 语句的一种优化策略。
*   **接口方法调用**: `getClosureAndRcvr` 和 `call` 函数中对 `OCALLINTER` 的处理实现了接口方法的调用机制.

**Go 代码举例说明:**

```go
package main

func main() {
    x := 10
    y := 20
    var z int

    // 对应 assign
    z = x + y

    // 对应 condBranch
    if x < y {
        println("x is less than y")
    } else {
        println("x is not less than y")
    }

    // 对应 zeroVal
    var a int
    var b string
    println(a) // 输出 0
    println(b == "") // 输出 true

    // 假设 println 是一个 intrinsic 函数 (实际可能不是)
    println(z)
}

type MyStruct struct {
    A int
    B string
}

func testDefer() {
    s := MyStruct{A: 1, B: "hello"}
    // 对应 assign 中结构体字段的赋值
    s.A = 100
    defer println("deferred") // 对应 openDeferRecord 等
    println(s.A)
}

func add(a, b float32) float32 {
    return a + b // 如果是软浮点架构，可能会用到 sfcall
}

type MyInterface interface {
    Method()
}

type MyType struct{}

func (m MyType) Method() {}

func testInterface(i MyInterface) {
    // 对应 OCALLINTER 和 getClosureAndRcvr
    i.Method()
}
```

**假设的输入与输出 (SSA 表示):**

由于 SSA 的输出非常复杂且依赖于具体的编译器实现和优化，这里提供一个非常简化的示意：

对于 `z = x + y`:

```
v1 = load x
v2 = load y
v3 = add v1, v2
store v3, z
```

对于 `if x < y`:

```
v4 = load x
v5 = load y
v6 = less v4, v5
br v6, block_true, block_false
block_true:
    // ... println("x is less than y") 的 SSA ...
    goto block_end
block_false:
    // ... println("x is not less than y") 的 SSA ...
    goto block_end
block_end:
```

**命令行参数的具体处理:**

这一部分代码本身不直接处理命令行参数。命令行参数的处理通常发生在编译器的其他阶段，例如词法分析、语法分析和类型检查。`ssagen` 阶段接收的是已经过处理的抽象语法树（AST）。

**使用者易犯错的点 (与本部分功能相关的):**

*   **对 `defer` 执行顺序的误解**:  虽然代码中展示了 `openDefer` 的处理，但用户可能会忘记 `defer` 语句是逆序执行的。
*   **接口类型的理解**: 用户可能不清楚接口方法调用时，编译器需要获取接口的 `itab` 和数据指针，这部分由 `getClosureAndRcvr` 处理。
*   **结构体赋值的性能影响**: 大结构体的赋值可能会涉及较多的内存操作，用户可能需要考虑使用指针来优化。

**功能归纳:**

总而言之，`go/src/cmd/compile/internal/ssagen/ssa.go` 的第 5 部分专注于将 Go 语言中的**控制流语句（主要是条件分支）**和**赋值语句**转换成底层的 SSA 中间表示形式。它还涉及一些特殊的函数调用处理（如软浮点和内联函数）以及 `defer` 语句的一种优化实现策略。 这部分代码是 Go 编译器将高级 Go 代码转换为可执行机器码的关键步骤之一。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssagen/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共8部分，请归纳一下它的功能

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
	if n.Op(
"""




```