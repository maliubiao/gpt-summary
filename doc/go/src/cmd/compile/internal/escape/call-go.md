Response: My thinking process to answer the request about `go/src/cmd/compile/internal/escape/call.go` went something like this:

1. **Understand the Goal:** The request asks for the functionality of the provided Go code snippet, its relation to Go language features, code examples, handling of command-line arguments (if any), and common mistakes users might make.

2. **Identify the Core Functionality:** The package is named `escape`, and the file `call.go` contains a central function `call(ks []hole, call ir.Node)`. The comments clearly state that this function "evaluates call expressions, including builtin calls." This is the primary function to focus on.

3. **Break Down the `call` Function:** I scanned the `switch` statement within `call`. Each `case` handles a different type of call (`ir.OCALLFUNC`, `ir.OCALLINTER`, `ir.OINLCALL`, `ir.OAPPEND`, etc.). This immediately tells me the code is responsible for analyzing various call scenarios.

4. **Analyze Each `case`:** I went through each `case` to understand what it does. I paid attention to:
    * **The type of call being handled:**  Function calls, interface calls, inlined calls, built-in functions like `append`, `copy`, `panic`, etc.
    * **How arguments are processed:**  The `argument` and `argumentParam` functions are crucial. They seem to track how data flows into function parameters.
    * **The role of `hole`:** The `hole` type appears to be a way of tracking escape information. The comments like "holes representing where the function callee's results flows" and the functions like `teeHole`, `heapHole`, `mutatorHole`, `discardHole`, `calleeHole` are strong indicators.
    * **Specific handling for built-ins:**  The code has specific logic for functions like `append`, `copy`, `panic`, and even specific built-ins related to `hash/maphash`.
    * **The `rewriteArgument` function:** This function looks like it modifies arguments based on function pragmas, particularly concerning `uintptr` conversions.

5. **Connect to Go Language Features:** Based on the analysis of the `call` function, it became clear that this code is a crucial part of **escape analysis** in the Go compiler. Escape analysis determines whether a variable's memory needs to be allocated on the heap or if it can reside on the stack. The handling of `go` and `defer` statements in `goDeferStmt` further confirms this. The special handling of built-in functions is also characteristic of compiler optimizations.

6. **Infer Go Examples:**  With the understanding of escape analysis, I could devise examples illustrating the concepts:
    * **Basic function call:**  Demonstrate how arguments are passed.
    * **Call with `append`:** Show how `append` might or might not allocate on the heap.
    * **Call with `copy`:** Illustrate how `copy` handles data.
    * **`go` and `defer` statements:** Show the allocation behavior.
    * **`uintptr` usage:**  Highlight the special handling of `unsafe.Pointer` to `uintptr` conversions.

7. **Command-Line Arguments:** I scanned the code for any interaction with `os.Args` or similar mechanisms for parsing command-line flags. I found none, so I concluded that this specific code snippet doesn't directly handle command-line arguments. However, I knew that the overall compilation process *does* have command-line arguments that influence optimizations like escape analysis. I made sure to include this distinction in the answer.

8. **Common Mistakes:** Thinking about how escape analysis works, I considered potential pitfalls for developers. The key is that forcing variables to escape to the heap can have performance implications. The example of unintentionally causing allocations within loops came to mind as a classic case. Also, misunderstandings about how `uintptr` interacts with the garbage collector are common.

9. **Structure the Answer:**  I organized the information into the requested categories: functionality, Go language feature, code examples, command-line arguments, and common mistakes. I used clear headings and bullet points for readability.

10. **Refine and Review:** I reviewed my answer to ensure accuracy, clarity, and completeness. I made sure the code examples were concise and directly illustrated the points being made. I paid attention to the specific wording of the request to ensure I addressed all aspects. For example, explicitly mentioning the *absence* of direct command-line argument handling is important.

By following these steps, I was able to break down the complex code into understandable components and provide a comprehensive answer to the request. The key was to focus on the core purpose of the code (escape analysis) and then connect the individual parts to that overall goal.
这段代码是 Go 编译器中 **逃逸分析 (Escape Analysis)** 的一部分，专门负责分析函数调用表达式。逃逸分析的目标是确定变量的生命周期，并决定在栈上还是堆上分配内存。

**功能列表:**

1. **分析各种类型的函数调用:** 包括普通函数调用 (`ir.OCALLFUNC`)、接口方法调用 (`ir.OCALLINTER`) 和内联函数调用 (`ir.OINLCALL`)。
2. **处理内置函数调用:**  针对 Go 语言的内置函数（如 `append`, `copy`, `panic`, `len`, `cap` 等）进行特殊的逃逸分析处理。
3. **跟踪函数参数的逃逸:**  确定函数调用的参数是否会逃逸到堆上。
4. **跟踪函数返回值的逃逸:** 确定函数调用的返回值是否会逃逸到堆上。
5. **处理 `go` 和 `defer` 语句:** 分析 `go` 关键字启动的 goroutine 和 `defer` 语句调用的函数的参数逃逸情况。
6. **处理与 `unsafe.Pointer` 相关的转换:**  特别关注 `uintptr(ptr)` 这种将 `unsafe.Pointer` 转换为 `uintptr` 的操作，并根据编译器的 pragma 指令 (`//go:uintptrescapes`, `//go:uintptrkeepalive`) 来决定是否需要保持指针的活跃状态或强制其逃逸。
7. **处理 `hash/maphash.escapeForHash`:**  针对 `hash/maphash.escapeForHash` 函数进行特殊处理，确保如果参数包含非字符串指针，则会被强制分配到堆上。
8. **处理 `append` 操作:**  分析 `append` 操作，判断底层的切片是否需要重新分配到堆上，以及追加的元素是否会逃逸。
9. **处理 `copy` 操作:** 分析 `copy` 操作，判断源切片中的元素是否会逃逸。

**它是什么 Go 语言功能的实现：逃逸分析**

这段代码是 Go 编译器进行逃逸分析的关键部分。逃逸分析是 Go 编译器的一项重要优化技术，它可以显著提高程序的性能并减少垃圾回收的压力。通过分析变量的使用方式，编译器可以决定将变量分配在栈上还是堆上。栈上的内存分配和回收速度更快，且无需垃圾回收器的介入。

**Go 代码举例说明:**

```go
package main

import "fmt"

func foo() *int {
	x := 10
	return &x // x 逃逸到堆上，因为它的地址被返回
}

func bar() int {
	y := 20
	return y // y 没有逃逸，可以在栈上分配
}

func main() {
	p := foo()
	fmt.Println(*p)

	q := bar()
	fmt.Println(q)
}

func withAppend() []int {
	s := make([]int, 0, 5)
	s = append(s, 1) // 如果切片容量足够，可能不会重新分配到堆上
	return s
}

func withCopy() {
	src := []int{1, 2, 3}
	dst := make([]int, len(src))
	copy(dst, src) // src 中的元素是否逃逸取决于具体情况
	fmt.Println(dst)
}

func withGo() {
	x := 42
	go func() { // x 逃逸到堆上，因为在 goroutine 中被引用
		fmt.Println(x)
	}()
}

func withDefer() {
	x := 100
	defer fmt.Println(x) // x 逃逸到堆上，需要在函数返回后仍然有效
}

type MyStruct struct {
	Data int
}

func escapeForHashExample() {
	m := make(map[*MyStruct]int)
	s := &MyStruct{Data: 5}
	m[s] = 1 // 指针类型的 key 会逃逸到堆上
}
```

**假设的输入与输出（代码推理）:**

假设 `call` 函数接收到一个代表函数调用的 `ir.Node` 和一个 `hole` 切片 `ks`，用于表示函数返回值的逃逸位置。

**输入 (示例 - `foo()` 函数调用):**

* `call`: 一个 `*ir.CallExpr` 类型的节点，表示对 `foo()` 函数的调用。
* `ks`: 一个长度为 1 的 `hole` 切片，表示 `foo()` 函数的返回值 ( `*int` ) 的逃逸位置。

**处理过程 (简化):**

1. 代码识别出这是一个 `ir.OCALLFUNC` 类型的调用。
2. 它会获取被调用函数 `foo` 的信息。
3. 由于 `foo` 返回的是一个指向局部变量 `x` 的指针，逃逸分析会判断 `x` 必须逃逸到堆上，以保证在 `foo` 函数返回后，指针仍然有效。
4. `e.expr(ks[0], result.Nname.(*ir.Name))` 这行代码会将返回值 `&x` 的逃逸信息与 `ks[0]` 这个 `hole` 关联起来，表明返回值会流向 `ks[0]` 指示的位置（很可能是堆）。

**输出 (通过 `hole` 的状态变化反映):**

* `ks[0]` 这个 `hole` 的状态会被标记为需要分配在堆上。

**输入 (示例 - `bar()` 函数调用):**

* `call`: 一个 `*ir.CallExpr` 类型的节点，表示对 `bar()` 函数的调用。
* `ks`: 一个长度为 1 的 `hole` 切片，表示 `bar()` 函数的返回值 ( `int` ) 的逃逸位置。

**处理过程 (简化):**

1. 代码识别出这是一个 `ir.OCALLFUNC` 类型的调用。
2. 它会获取被调用函数 `bar` 的信息。
3. 由于 `bar` 返回的是一个值类型 `int`，且没有被外部引用，逃逸分析会判断 `y` 不需要逃逸到堆上。
4. `e.expr(ks[0], result.Nname.(*ir.Name))` 这行代码会将返回值 `y` 的逃逸信息与 `ks[0]` 关联，但由于 `y` 没有逃逸，`ks[0]` 可能仍然指向栈或者被标记为不需要额外分配。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。逃逸分析是 Go 编译器的一个编译阶段，它受到一些编译器标志的影响，例如：

* **`-gcflags=-m` 或 `-gcflags=-m -m`:**  这些标志会使编译器在编译过程中打印逃逸分析的决策信息。开发者可以通过这些信息来了解哪些变量逃逸到了堆上。

   ```bash
   go build -gcflags=-m main.go
   ```

   输出可能包含类似如下的信息：

   ```
   ./main.go:8:6: moved to heap: x
   ./main.go:13:6: y does not escape
   ./main.go:20:12: make([]int, 0, 5) does not escape
   ./main.go:35:13: func literal escapes to heap
   ./main.go:36:14: x escapes to heap
   ./main.go:42:17: x escapes to heap
   ./main.go:50:10: &MyStruct literal escapes to heap
   ```

**使用者易犯错的点:**

开发者通常不需要直接与这段代码交互，但理解逃逸分析的原理对于编写高性能的 Go 代码至关重要。一些常见的误解或易犯的错误包括：

1. **过度关注逃逸:**  虽然减少不必要的堆分配很重要，但过分追求将所有变量都分配在栈上可能会导致代码可读性降低或引入不必要的复杂性。编译器在逃逸分析方面已经做得相当出色。
2. **错误地认为所有局部变量都在栈上:**  如上面的 `foo()` 和 `withGo()` 的例子所示，即使是局部变量，如果其地址被返回或在 goroutine 中被引用，也会逃逸到堆上。
3. **对 `defer` 的误解:**  `defer` 语句中引用的变量通常会逃逸到堆上，因为它们需要在函数返回后仍然有效。
4. **不理解 `uintptr` 的特殊性:**  在与 C 代码互操作或进行底层操作时使用 `uintptr` 需要特别小心。编译器会根据 pragma 指令来决定如何处理 `uintptr` 类型的参数，错误的使用可能导致内存安全问题或性能下降。

**示例说明 `uintptr` 的易错点:**

假设有以下代码：

```go
package main

import "fmt"
import "unsafe"

func main() {
	data := []int{1, 2, 3}
	ptr := unsafe.Pointer(&data[0])
	uptr := uintptr(ptr)

	// 假设在某个时刻，data 可能被垃圾回收器移动了

	// 错误地使用 uptr 访问数据
	wrongPtr := unsafe.Pointer(uptr)
	element := *(*int)(wrongPtr)
	fmt.Println(element) // 可能输出错误的值或者导致程序崩溃
}
```

在这个例子中，将 `&data[0]` 转换为 `uintptr` 后，`uptr` 只是一个数值，不再与 `data` 切片的生命周期关联。如果 `data` 切片在之后被垃圾回收器移动，`uptr` 指向的内存地址可能已经无效，导致访问错误。编译器可以通过 `//go:uintptrkeepalive` pragma 来解决这类问题，确保在特定操作期间，指针指向的内存不会被回收。

总而言之，这段 `call.go` 文件是 Go 编译器逃逸分析的核心组件，它负责理解函数调用的语义，并根据变量的使用方式来决定其内存分配的位置，从而优化程序的性能和内存管理。开发者理解逃逸分析的原理有助于编写更高效、更可靠的 Go 代码。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/escape/call.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package escape

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/src"
	"strings"
)

// call evaluates a call expressions, including builtin calls. ks
// should contain the holes representing where the function callee's
// results flows.
func (e *escape) call(ks []hole, call ir.Node) {
	argument := func(k hole, arg ir.Node) {
		// TODO(mdempsky): Should be "call argument".
		e.expr(k.note(call, "call parameter"), arg)
	}

	switch call.Op() {
	default:
		ir.Dump("esc", call)
		base.Fatalf("unexpected call op: %v", call.Op())

	case ir.OCALLFUNC, ir.OCALLINTER:
		call := call.(*ir.CallExpr)
		typecheck.AssertFixedCall(call)

		// Pick out the function callee, if statically known.
		//
		// TODO(mdempsky): Change fn from *ir.Name to *ir.Func, but some
		// functions (e.g., runtime builtins, method wrappers, generated
		// eq/hash functions) don't have it set. Investigate whether
		// that's a concern.
		var fn *ir.Name
		switch call.Op() {
		case ir.OCALLFUNC:
			v := ir.StaticValue(call.Fun)
			fn = ir.StaticCalleeName(v)
		}

		fntype := call.Fun.Type()
		if fn != nil {
			fntype = fn.Type()
		}

		if ks != nil && fn != nil && e.inMutualBatch(fn) {
			for i, result := range fn.Type().Results() {
				e.expr(ks[i], result.Nname.(*ir.Name))
			}
		}

		var recvArg ir.Node
		if call.Op() == ir.OCALLFUNC {
			// Evaluate callee function expression.
			calleeK := e.discardHole()
			if fn == nil { // unknown callee
				for _, k := range ks {
					if k.dst != &e.blankLoc {
						// The results flow somewhere, but we don't statically
						// know the callee function. If a closure flows here, we
						// need to conservatively assume its results might flow to
						// the heap.
						calleeK = e.calleeHole().note(call, "callee operand")
						break
					}
				}
			}
			e.expr(calleeK, call.Fun)
		} else {
			recvArg = call.Fun.(*ir.SelectorExpr).X
		}

		// argumentParam handles escape analysis of assigning a call
		// argument to its corresponding parameter.
		argumentParam := func(param *types.Field, arg ir.Node) {
			e.rewriteArgument(arg, call, fn)
			argument(e.tagHole(ks, fn, param), arg)
		}

		// hash/maphash.escapeForHash forces its argument to be on
		// the heap, if it contains a non-string pointer. We cannot
		// hash pointers to local variables, as the address of the
		// local variable might change on stack growth.
		// Strings are okay as the hash depends on only the content,
		// not the pointer.
		// The actual call we match is
		//   hash/maphash.escapeForHash[go.shape.T](dict, go.shape.T)
		if fn != nil && fn.Sym().Pkg.Path == "hash/maphash" && strings.HasPrefix(fn.Sym().Name, "escapeForHash[") {
			ps := fntype.Params()
			if len(ps) == 2 && ps[1].Type.IsShape() {
				if !hasNonStringPointers(ps[1].Type) {
					argumentParam = func(param *types.Field, arg ir.Node) {
						argument(e.discardHole(), arg)
					}
				} else {
					argumentParam = func(param *types.Field, arg ir.Node) {
						argument(e.heapHole(), arg)
					}
				}
			}
		}

		args := call.Args
		if recvParam := fntype.Recv(); recvParam != nil {
			if recvArg == nil {
				// Function call using method expression. Receiver argument is
				// at the front of the regular arguments list.
				recvArg, args = args[0], args[1:]
			}

			argumentParam(recvParam, recvArg)
		}

		for i, param := range fntype.Params() {
			argumentParam(param, args[i])
		}

	case ir.OINLCALL:
		call := call.(*ir.InlinedCallExpr)
		e.stmts(call.Body)
		for i, result := range call.ReturnVars {
			k := e.discardHole()
			if ks != nil {
				k = ks[i]
			}
			e.expr(k, result)
		}

	case ir.OAPPEND:
		call := call.(*ir.CallExpr)
		args := call.Args

		// Appendee slice may flow directly to the result, if
		// it has enough capacity. Alternatively, a new heap
		// slice might be allocated, and all slice elements
		// might flow to heap.
		appendeeK := e.teeHole(ks[0], e.mutatorHole())
		if args[0].Type().Elem().HasPointers() {
			appendeeK = e.teeHole(appendeeK, e.heapHole().deref(call, "appendee slice"))
		}
		argument(appendeeK, args[0])

		if call.IsDDD {
			appendedK := e.discardHole()
			if args[1].Type().IsSlice() && args[1].Type().Elem().HasPointers() {
				appendedK = e.heapHole().deref(call, "appended slice...")
			}
			argument(appendedK, args[1])
		} else {
			for i := 1; i < len(args); i++ {
				argument(e.heapHole(), args[i])
			}
		}
		e.discard(call.RType)

	case ir.OCOPY:
		call := call.(*ir.BinaryExpr)
		argument(e.mutatorHole(), call.X)

		copiedK := e.discardHole()
		if call.Y.Type().IsSlice() && call.Y.Type().Elem().HasPointers() {
			copiedK = e.heapHole().deref(call, "copied slice")
		}
		argument(copiedK, call.Y)
		e.discard(call.RType)

	case ir.OPANIC:
		call := call.(*ir.UnaryExpr)
		argument(e.heapHole(), call.X)

	case ir.OCOMPLEX:
		call := call.(*ir.BinaryExpr)
		e.discard(call.X)
		e.discard(call.Y)

	case ir.ODELETE, ir.OPRINT, ir.OPRINTLN, ir.ORECOVERFP:
		call := call.(*ir.CallExpr)
		for _, arg := range call.Args {
			e.discard(arg)
		}
		e.discard(call.RType)

	case ir.OMIN, ir.OMAX:
		call := call.(*ir.CallExpr)
		for _, arg := range call.Args {
			argument(ks[0], arg)
		}
		e.discard(call.RType)

	case ir.OLEN, ir.OCAP, ir.OREAL, ir.OIMAG, ir.OCLOSE:
		call := call.(*ir.UnaryExpr)
		e.discard(call.X)

	case ir.OCLEAR:
		call := call.(*ir.UnaryExpr)
		argument(e.mutatorHole(), call.X)

	case ir.OUNSAFESTRINGDATA, ir.OUNSAFESLICEDATA:
		call := call.(*ir.UnaryExpr)
		argument(ks[0], call.X)

	case ir.OUNSAFEADD, ir.OUNSAFESLICE, ir.OUNSAFESTRING:
		call := call.(*ir.BinaryExpr)
		argument(ks[0], call.X)
		e.discard(call.Y)
		e.discard(call.RType)
	}
}

// goDeferStmt analyzes a "go" or "defer" statement.
func (e *escape) goDeferStmt(n *ir.GoDeferStmt) {
	k := e.heapHole()
	if n.Op() == ir.ODEFER && e.loopDepth == 1 && n.DeferAt == nil {
		// Top-level defer arguments don't escape to the heap,
		// but they do need to last until they're invoked.
		k = e.later(e.discardHole())

		// force stack allocation of defer record, unless
		// open-coded defers are used (see ssa.go)
		n.SetEsc(ir.EscNever)
	}

	// If the function is already a zero argument/result function call,
	// just escape analyze it normally.
	//
	// Note that the runtime is aware of this optimization for
	// "go" statements that start in reflect.makeFuncStub or
	// reflect.methodValueCall.

	call, ok := n.Call.(*ir.CallExpr)
	if !ok || call.Op() != ir.OCALLFUNC {
		base.FatalfAt(n.Pos(), "expected function call: %v", n.Call)
	}
	if sig := call.Fun.Type(); sig.NumParams()+sig.NumResults() != 0 {
		base.FatalfAt(n.Pos(), "expected signature without parameters or results: %v", sig)
	}

	if clo, ok := call.Fun.(*ir.ClosureExpr); ok && n.Op() == ir.OGO {
		clo.IsGoWrap = true
	}

	e.expr(k, call.Fun)
}

// rewriteArgument rewrites the argument arg of the given call expression.
// fn is the static callee function, if known.
func (e *escape) rewriteArgument(arg ir.Node, call *ir.CallExpr, fn *ir.Name) {
	if fn == nil || fn.Func == nil {
		return
	}
	pragma := fn.Func.Pragma
	if pragma&(ir.UintptrKeepAlive|ir.UintptrEscapes) == 0 {
		return
	}

	// unsafeUintptr rewrites "uintptr(ptr)" arguments to syscall-like
	// functions, so that ptr is kept alive and/or escaped as
	// appropriate. unsafeUintptr also reports whether it modified arg0.
	unsafeUintptr := func(arg ir.Node) {
		// If the argument is really a pointer being converted to uintptr,
		// arrange for the pointer to be kept alive until the call
		// returns, by copying it into a temp and marking that temp still
		// alive when we pop the temp stack.
		conv, ok := arg.(*ir.ConvExpr)
		if !ok || conv.Op() != ir.OCONVNOP {
			return // not a conversion
		}
		if !conv.X.Type().IsUnsafePtr() || !conv.Type().IsUintptr() {
			return // not an unsafe.Pointer->uintptr conversion
		}

		// Create and declare a new pointer-typed temp variable.
		//
		// TODO(mdempsky): This potentially violates the Go spec's order
		// of evaluations, by evaluating arg.X before any other
		// operands.
		tmp := e.copyExpr(conv.Pos(), conv.X, call.PtrInit())
		conv.X = tmp

		k := e.mutatorHole()
		if pragma&ir.UintptrEscapes != 0 {
			k = e.heapHole().note(conv, "//go:uintptrescapes")
		}
		e.flow(k, e.oldLoc(tmp))

		if pragma&ir.UintptrKeepAlive != 0 {
			tmp.SetAddrtaken(true) // ensure SSA keeps the tmp variable
			call.KeepAlive = append(call.KeepAlive, tmp)
		}
	}

	// For variadic functions, the compiler has already rewritten:
	//
	//     f(a, b, c)
	//
	// to:
	//
	//     f([]T{a, b, c}...)
	//
	// So we need to look into slice elements to handle uintptr(ptr)
	// arguments to variadic syscall-like functions correctly.
	if arg.Op() == ir.OSLICELIT {
		list := arg.(*ir.CompLitExpr).List
		for _, el := range list {
			if el.Op() == ir.OKEY {
				el = el.(*ir.KeyExpr).Value
			}
			unsafeUintptr(el)
		}
	} else {
		unsafeUintptr(arg)
	}
}

// copyExpr creates and returns a new temporary variable within fn;
// appends statements to init to declare and initialize it to expr;
// and escape analyzes the data flow.
func (e *escape) copyExpr(pos src.XPos, expr ir.Node, init *ir.Nodes) *ir.Name {
	if ir.HasUniquePos(expr) {
		pos = expr.Pos()
	}

	tmp := typecheck.TempAt(pos, e.curfn, expr.Type())

	stmts := []ir.Node{
		ir.NewDecl(pos, ir.ODCL, tmp),
		ir.NewAssignStmt(pos, tmp, expr),
	}
	typecheck.Stmts(stmts)
	init.Append(stmts...)

	e.newLoc(tmp, true)
	e.stmts(stmts)

	return tmp
}

// tagHole returns a hole for evaluating an argument passed to param.
// ks should contain the holes representing where the function
// callee's results flows. fn is the statically-known callee function,
// if any.
func (e *escape) tagHole(ks []hole, fn *ir.Name, param *types.Field) hole {
	// If this is a dynamic call, we can't rely on param.Note.
	if fn == nil {
		return e.heapHole()
	}

	if e.inMutualBatch(fn) {
		if param.Nname == nil {
			return e.discardHole()
		}
		return e.addr(param.Nname.(*ir.Name))
	}

	// Call to previously tagged function.

	var tagKs []hole
	esc := parseLeaks(param.Note)

	if x := esc.Heap(); x >= 0 {
		tagKs = append(tagKs, e.heapHole().shift(x))
	}
	if x := esc.Mutator(); x >= 0 {
		tagKs = append(tagKs, e.mutatorHole().shift(x))
	}
	if x := esc.Callee(); x >= 0 {
		tagKs = append(tagKs, e.calleeHole().shift(x))
	}

	if ks != nil {
		for i := 0; i < numEscResults; i++ {
			if x := esc.Result(i); x >= 0 {
				tagKs = append(tagKs, ks[i].shift(x))
			}
		}
	}

	return e.teeHole(tagKs...)
}

func hasNonStringPointers(t *types.Type) bool {
	if !t.HasPointers() {
		return false
	}
	switch t.Kind() {
	case types.TSTRING:
		return false
	case types.TSTRUCT:
		for _, f := range t.Fields() {
			if hasNonStringPointers(f.Type) {
				return true
			}
		}
		return false
	case types.TARRAY:
		return hasNonStringPointers(t.Elem())
	}
	return true
}

"""



```