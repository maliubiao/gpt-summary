Response:
Let's break down the request and the provided Go code to generate a comprehensive response.

**1. Understanding the Request:**

The core request is to analyze a specific Go source file (`go/src/cmd/compile/internal/typecheck/func.go`) and describe its functionalities. The prompt also requests specific types of information:

* **Functionality Listing:** A straightforward enumeration of what the code does.
* **Go Feature Implementation:** Identifying which high-level Go language features this code contributes to and providing illustrative Go code examples.
* **Code Reasoning (with Input/Output):** If the code manipulates data structures or performs transformations, the prompt asks for examples with hypothetical inputs and expected outputs.
* **Command-Line Arguments:**  Explanation of any command-line flags that might influence this code's behavior.
* **Common Mistakes:** Identifying potential pitfalls or errors developers might encounter related to the functionality of this code.

**2. Initial Code Scan and High-Level Understanding:**

A quick skim of the code reveals several key areas:

* **`MakeDotArgs`:**  Deals with packing variadic arguments into a slice.
* **`FixVariadicCall`:** Modifies calls to variadic functions to explicitly pass a slice for the `...` arguments.
* **`FixMethodCall`:** Transforms method calls (`t.M(...)`) into regular function calls (`T.M(t, ...)`).
* **`AssertFixedCall`:**  Performs assertions to ensure the previous transformations have occurred.
* **`ClosureType`:**  Generates the struct type representing a closure, capturing the necessary variables.
* **`MethodValueType`:**  Similar to `ClosureType` but for method values.
* **`tcFunc`:**  Type-checks function definitions.
* **`tcCall`:** Type-checks function calls, including built-ins and type conversions.
* **`tcAppend`, `tcClear`, `tcClose`, ..., `tcUnsafeString`:**  Type-checking implementations for various built-in functions and language constructs (like `append`, `make`, `delete`, etc.).

**3. Deeper Dive and Feature Mapping:**

Now, let's connect the code sections to specific Go language features:

* **Variadic Functions:** `MakeDotArgs` and `FixVariadicCall` are clearly related to how Go handles functions that accept a variable number of arguments.
* **Methods:** `FixMethodCall` and `MethodValueType` are involved in the compilation process of methods in Go.
* **Closures:** `ClosureType` directly implements the underlying mechanism for creating and representing closures.
* **Function Calls:** `tcCall` is the core of type-checking function invocations.
* **Built-in Functions:** The `tcAppend`, `tcMake`, `tcDelete`, etc., functions are responsible for type-checking calls to Go's built-in functions.
* **Type Conversions:** The `tcCall` function handles the type-checking of explicit type conversions.
* **`unsafe` Package:** The `tcUnsafeAdd`, `tcUnsafeSlice`, and `tcUnsafeString` functions deal with the type-checking of operations in the `unsafe` package.
* **`make`, `new`, `delete`:**  The corresponding `tc...` functions handle the type-checking for these built-in allocation and deallocation operations.
* **`panic`, `recover`, `print`, `println`:** The corresponding `tc...` functions handle the type-checking for these built-in error handling and output functions.
* **`complex`, `real`, `imag`, `copy`:** The corresponding `tc...` functions handle the type-checking for these built-in complex number and data manipulation functions.

**4. Generating Examples and Reasoning:**

For each identified feature, construct simple Go code examples demonstrating the functionality being type-checked by the code in `func.go`. For code reasoning, devise hypothetical inputs (AST nodes, function call structures) and the expected outputs after the type-checking process.

**5. Considering Command-Line Arguments:**

The code itself doesn't directly parse command-line arguments. However, it interacts with the `base` package, which *does* handle command-line flags. The `base.EnableTrace` and `base.Flag.LowerT` variables suggest that the `-N` (disable optimizations) and possibly `-l` (disable inlining) flags might influence the execution flow within this file, although the exact impact might require deeper inspection of the `base` package.

**6. Identifying Common Mistakes:**

Think about common errors developers make when using the Go features handled by this code. For instance:

* **Incorrect usage of `...` in variadic calls.**
* **Type mismatches in arguments to built-in functions.**
* **Trying to `make` types that are not slices, maps, or channels.**
* **Incorrectly using the `unsafe` package.**

**7. Structuring the Response:**

Organize the information logically:

* Start with a general overview of the file's purpose.
* List the key functions and their individual functionalities.
* Dedicate sections to each major Go language feature, providing explanations, examples, and code reasoning where applicable.
* Address command-line arguments and common mistakes.
* Use code blocks and clear formatting to enhance readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the individual functions in the file.
* **Correction:** Realize that the functions are interconnected and contribute to higher-level Go features. Group the analysis by feature rather than just listing function descriptions.
* **Initial thought:**  Assume command-line arguments are directly handled within the file.
* **Correction:** Recognize the dependency on the `base` package and investigate how flags in `base` might affect the code's behavior indirectly.
* **Initial thought:**  Provide very detailed internal workings of each function.
* **Correction:**  Focus on the *observable* behavior and the Go language features being implemented, avoiding excessive low-level compiler details unless explicitly requested or necessary for understanding. The prompt emphasizes the *functionality* and how it relates to the *user* and Go language features.

By following this thought process, iterating through understanding and refinement, we can construct a comprehensive and accurate answer to the user's request.
这段代码是Go编译器 `cmd/compile/internal/typecheck` 包中 `func.go` 文件的一部分，主要负责 **类型检查阶段** 中与 **函数和方法调用** 相关的处理。它确保了函数和方法的调用是合法的，并且根据需要进行一些转换和重写。

以下是它的一些主要功能：

1. **处理变参函数调用 (`MakeDotArgs`, `FixVariadicCall`)**:
   - `MakeDotArgs` 将匹配变参 `...T` 的所有参数打包成一个 `[]T` 类型的切片。
   - `FixVariadicCall` 检查对变参函数的调用，如果参数列表中没有显式使用 `...` 传递切片，则将额外的参数打包成一个切片并替换调用参数。

2. **处理方法调用 (`FixMethodCall`)**:
   - `FixMethodCall` 将方法调用 `t.M(...)` 重写为函数调用 `T.M(t, ...)`，即将接收者 `t` 作为函数的第一个参数传递。

3. **断言调用已修复 (`AssertFixedCall`)**:
   - `AssertFixedCall` 用于在类型检查的后续阶段进行断言，确保变参调用和方法调用已经被 `FixVariadicCall` 和 `FixMethodCall` 正确处理。

4. **创建闭包类型 (`ClosureType`)**:
   - `ClosureType` 为闭包表达式 (`OCLOSURE` 节点) 生成一个结构体类型，用于存储闭包捕获的变量。这个结构体包含一个指向函数入口的指针 `F`，以及捕获的变量。

5. **创建方法值类型 (`MethodValueType`)**:
   - `MethodValueType` 为方法值表达式 (`OMETHVALUE` 节点) 生成一个结构体类型，用于存储方法和接收者。

6. **类型检查函数定义 (`tcFunc`)**:
   - `tcFunc` (实际上应该通过 `typecheck.Func` 调用) 负责对函数定义进行类型检查。

7. **类型检查函数调用 (`tcCall`)**:
   - `tcCall` 是核心函数，负责类型检查 `OCALL` 节点 (函数调用)。
   - 它处理内置函数 (如 `len`, `cap`, `append` 等) 的特殊情况。
   - 它处理类型转换。
   - 它调用 `RewriteNonNameCall` (未在此代码段中显示) 处理间接函数调用。
   - 它调用 `typecheckargs` (未在此代码段中显示) 类型检查函数参数。
   - 它处理接口方法调用 (`ODOTINTER`) 和普通方法调用 (`ODOTMETH`)。
   - 它调用 `typecheckaste` (未在此代码段中显示) 检查参数数量和类型是否与函数签名匹配。

8. **类型检查内置函数 (`tcAppend`, `tcClear`, `tcClose`, ..., `tcUnsafeString`)**:
   - 针对每个内置函数 (如 `append`, `clear`, `close`, `complex`, `copy`, `delete`, `make`, `new`, `panic`, `print`, `println`, `real`, `imag`, `recover`, 以及 `unsafe` 包中的函数) 都有对应的 `tc...` 函数进行特定的类型检查。这些函数会检查参数类型、数量，并进行必要的类型转换。

**它可以推理出是什么Go语言功能的实现：**

这段代码是 Go 语言中 **函数调用、方法调用、闭包和内置函数** 功能的类型检查实现。

**Go 代码举例说明：**

```go
package main

import "fmt"

func add(a, b int) int {
	return a + b
}

func sum(nums ...int) int { // 变参函数
	total := 0
	for _, n := range nums {
		total += n
	}
	return total
}

type MyInt int

func (mi MyInt) String() string { // 方法
	return fmt.Sprintf("MyInt(%d)", mi)
}

func main() {
	// 普通函数调用
	result := add(5, 3)
	fmt.Println(result) // Output: 8

	// 变参函数调用
	sumResult := sum(1, 2, 3, 4)
	fmt.Println(sumResult) // Output: 10

	// 方法调用
	var myNum MyInt = 10
	str := myNum.String()
	fmt.Println(str) // Output: MyInt(10)

	// 闭包
	multiplier := func(factor int) func(int) int {
		return func(x int) int {
			return x * factor
		}
	}
	multiplyBy5 := multiplier(5)
	fmt.Println(multiplyBy5(2)) // Output: 10

	// 内置函数调用
	numbers := []int{1, 2, 3}
	length := len(numbers)
	fmt.Println(length) // Output: 3

	appendedNumbers := append(numbers, 4)
	fmt.Println(appendedNumbers) // Output: [1 2 3 4]
}
```

**代码推理示例 (针对 `FixVariadicCall`)：**

**假设输入：**

一个 `ir.CallExpr` 类型的节点 `call`，表示对 `sum` 函数的调用，参数为 `ir.Node` 类型的节点数组 `[ir.NewInt(..., 1), ir.NewInt(..., 2), ir.NewInt(..., 3)]`。`call.Fun` 是 `sum` 函数的 `ir.Name` 节点，其类型 `fntype` 是 `func(...int) int`。 `call.IsDDD` 为 `false`。

**处理过程 (`FixVariadicCall`)：**

1. `fntype.IsVariadic()` 返回 `true`。
2. `call.IsDDD` 为 `false`，条件满足。
3. `vi` (变参参数的索引) 为 `fntype.NumParams() - 1 = 1 - 1 = 0`。
4. `vt` (变参参数的类型) 为 `fntype.Param(vi).Type`，即 `int`。
5. `args` 为 `call.Args`，即 `[ir.NewInt(..., 1), ir.NewInt(..., 2), ir.NewInt(..., 3)]`。
6. `extra` 为 `args[vi:]`，即 `[ir.NewInt(..., 1), ir.NewInt(..., 2), ir.NewInt(..., 3)]`。
7. `slice` 通过 `MakeDotArgs` 创建，类型为 `[]int`，包含 `extra` 中的元素。
8. 循环将 `extra` 中的元素置为 `nil`，允许 GC 回收。
9. `call.Args` 被更新为 `append(args[:vi], slice)`，即 `append([]ir.Node{}, slice)`，结果为包含 `slice` 的单个元素的切片，该元素是 `[]int` 类型的 `ir.CompLitExpr` 节点。
10. `call.IsDDD` 被设置为 `true`。

**输出：**

修改后的 `call` 节点，其 `call.Args` 为包含一个 `ir.CompLitExpr` 节点的切片，该节点表示 `[]int{1, 2, 3}`。`call.IsDDD` 为 `true`。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。但是，它依赖于 `cmd/compile/internal/base` 包，该包负责处理编译器的命令行参数。

例如，`base.EnableTrace` 和 `base.Flag.LowerT` 可能会受到编译器标志的影响，例如：

- `-N`：禁用优化，可能会影响某些类型检查的路径。
- `-l`：禁用内联，可能会影响函数调用的处理方式。
- 其他与类型检查和代码生成相关的标志。

具体的命令行参数处理逻辑在 `cmd/compile/internal/base` 包中定义，而这段代码会根据这些标志的状态执行不同的逻辑。

**使用者易犯错的点：**

这段代码是 Go 编译器内部的实现，直接的使用者是 Go 语言的开发者，而非普通的 Go 语言用户。

对于 Go 语言用户而言，与这段代码功能相关的易犯错误主要体现在以下方面：

1. **变参函数调用时 `...` 的使用错误：**
   - 忘记使用 `...` 将切片展开作为变参传递。
   - 在非变参函数调用时错误地使用了 `...`。
   ```go
   func printNumbers(nums ...int) {
       fmt.Println(nums)
   }

   func main() {
       numbers := []int{1, 2, 3}
       printNumbers(numbers...) // 正确：展开切片
       printNumbers(numbers)   // 错误：将切片作为单个参数传递
   }
   ```

2. **方法调用时接收者类型不匹配：**
   - 使用了错误的接收者类型调用方法。
   ```go
   type IntWrapper int

   func (iw IntWrapper) Double() int {
       return int(iw) * 2
   }

   func main() {
       var num int = 5
       // num.Double() // 错误：int 类型没有 Double 方法
       var wrapper IntWrapper = 5
       wrapper.Double() // 正确
   }
   ```

3. **闭包中捕获变量的生命周期理解不足：**
   - 在循环中使用闭包时，可能会错误地捕获循环变量的最终值。
   ```go
   func main() {
       funcs := []func(){}
       for i := 0; i < 5; i++ {
           funcs = append(funcs, func() {
               fmt.Println(i) // 错误：所有闭包都打印 5
           })
       }
       for _, f := range funcs {
           f()
       }

       funcs2 := []func(){}
       for i := 0; i < 5; i++ {
           x := i // 在循环内部创建局部变量
           funcs2 = append(funcs2, func() {
               fmt.Println(x) // 正确：每个闭包打印不同的值
           })
       }
       for _, f := range funcs2 {
           f()
       }
   }
   ```

4. **内置函数参数类型或数量错误：**
   - 调用内置函数时传递了错误类型的参数。
   - 调用内置函数时参数数量不正确。
   ```go
   func main() {
       numbers := []int{1, 2, 3}
       // length := len(10) // 错误：len 的参数必须是可计算长度的类型
       appended := append(numbers, "4") // 错误：append 的第二个参数类型不匹配
   }
   ```

总而言之，这段代码是 Go 编译器中负责确保函数和方法调用在类型层面是正确和合法的关键部分。它通过执行各种检查和转换，为后续的代码生成阶段奠定了基础。

### 提示词
```
这是路径为go/src/cmd/compile/internal/typecheck/func.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package typecheck

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/types"
	"cmd/internal/src"

	"fmt"
	"go/constant"
	"go/token"
)

// MakeDotArgs package all the arguments that match a ... T parameter into a []T.
func MakeDotArgs(pos src.XPos, typ *types.Type, args []ir.Node) ir.Node {
	if len(args) == 0 {
		return ir.NewNilExpr(pos, typ)
	}

	args = append([]ir.Node(nil), args...)
	lit := ir.NewCompLitExpr(pos, ir.OCOMPLIT, typ, args)
	lit.SetImplicit(true)

	n := Expr(lit)
	if n.Type() == nil {
		base.FatalfAt(pos, "mkdotargslice: typecheck failed")
	}
	return n
}

// FixVariadicCall rewrites calls to variadic functions to use an
// explicit ... argument if one is not already present.
func FixVariadicCall(call *ir.CallExpr) {
	fntype := call.Fun.Type()
	if !fntype.IsVariadic() || call.IsDDD {
		return
	}

	vi := fntype.NumParams() - 1
	vt := fntype.Param(vi).Type

	args := call.Args
	extra := args[vi:]
	slice := MakeDotArgs(call.Pos(), vt, extra)
	for i := range extra {
		extra[i] = nil // allow GC
	}

	call.Args = append(args[:vi], slice)
	call.IsDDD = true
}

// FixMethodCall rewrites a method call t.M(...) into a function call T.M(t, ...).
func FixMethodCall(call *ir.CallExpr) {
	if call.Fun.Op() != ir.ODOTMETH {
		return
	}

	dot := call.Fun.(*ir.SelectorExpr)

	fn := NewMethodExpr(dot.Pos(), dot.X.Type(), dot.Selection.Sym)

	args := make([]ir.Node, 1+len(call.Args))
	args[0] = dot.X
	copy(args[1:], call.Args)

	call.SetOp(ir.OCALLFUNC)
	call.Fun = fn
	call.Args = args
}

func AssertFixedCall(call *ir.CallExpr) {
	if call.Fun.Type().IsVariadic() && !call.IsDDD {
		base.FatalfAt(call.Pos(), "missed FixVariadicCall")
	}
	if call.Op() == ir.OCALLMETH {
		base.FatalfAt(call.Pos(), "missed FixMethodCall")
	}
}

// ClosureType returns the struct type used to hold all the information
// needed in the closure for clo (clo must be a OCLOSURE node).
// The address of a variable of the returned type can be cast to a func.
func ClosureType(clo *ir.ClosureExpr) *types.Type {
	// Create closure in the form of a composite literal.
	// supposing the closure captures an int i and a string s
	// and has one float64 argument and no results,
	// the generated code looks like:
	//
	//	clos = &struct{F uintptr; X0 *int; X1 *string}{func.1, &i, &s}
	//
	// The use of the struct provides type information to the garbage
	// collector so that it can walk the closure. We could use (in this
	// case) [3]unsafe.Pointer instead, but that would leave the gc in
	// the dark. The information appears in the binary in the form of
	// type descriptors; the struct is unnamed and uses exported field
	// names so that closures in multiple packages with the same struct
	// type can share the descriptor.

	fields := make([]*types.Field, 1+len(clo.Func.ClosureVars))
	fields[0] = types.NewField(base.AutogeneratedPos, types.LocalPkg.Lookup("F"), types.Types[types.TUINTPTR])
	it := NewClosureStructIter(clo.Func.ClosureVars)
	i := 0
	for {
		n, typ, _ := it.Next()
		if n == nil {
			break
		}
		fields[1+i] = types.NewField(base.AutogeneratedPos, types.LocalPkg.LookupNum("X", i), typ)
		i++
	}
	typ := types.NewStruct(fields)
	typ.SetNoalg(true)
	return typ
}

// MethodValueType returns the struct type used to hold all the information
// needed in the closure for a OMETHVALUE node. The address of a variable of
// the returned type can be cast to a func.
func MethodValueType(n *ir.SelectorExpr) *types.Type {
	t := types.NewStruct([]*types.Field{
		types.NewField(base.Pos, Lookup("F"), types.Types[types.TUINTPTR]),
		types.NewField(base.Pos, Lookup("R"), n.X.Type()),
	})
	t.SetNoalg(true)
	return t
}

// type check function definition
// To be called by typecheck, not directly.
// (Call typecheck.Func instead.)
func tcFunc(n *ir.Func) {
	if base.EnableTrace && base.Flag.LowerT {
		defer tracePrint("tcFunc", n)(nil)
	}

	if name := n.Nname; name.Typecheck() == 0 {
		base.AssertfAt(name.Type() != nil, n.Pos(), "missing type: %v", name)
		name.SetTypecheck(1)
	}
}

// tcCall typechecks an OCALL node.
func tcCall(n *ir.CallExpr, top int) ir.Node {
	Stmts(n.Init()) // imported rewritten f(g()) calls (#30907)
	n.Fun = typecheck(n.Fun, ctxExpr|ctxType|ctxCallee)

	l := n.Fun

	if l.Op() == ir.ONAME && l.(*ir.Name).BuiltinOp != 0 {
		l := l.(*ir.Name)
		if n.IsDDD && l.BuiltinOp != ir.OAPPEND {
			base.Errorf("invalid use of ... with builtin %v", l)
		}

		// builtin: OLEN, OCAP, etc.
		switch l.BuiltinOp {
		default:
			base.Fatalf("unknown builtin %v", l)

		case ir.OAPPEND, ir.ODELETE, ir.OMAKE, ir.OMAX, ir.OMIN, ir.OPRINT, ir.OPRINTLN, ir.ORECOVER:
			n.SetOp(l.BuiltinOp)
			n.Fun = nil
			n.SetTypecheck(0) // re-typechecking new op is OK, not a loop
			return typecheck(n, top)

		case ir.OCAP, ir.OCLEAR, ir.OCLOSE, ir.OIMAG, ir.OLEN, ir.OPANIC, ir.OREAL, ir.OUNSAFESTRINGDATA, ir.OUNSAFESLICEDATA:
			typecheckargs(n)
			fallthrough
		case ir.ONEW:
			arg, ok := needOneArg(n, "%v", n.Op())
			if !ok {
				n.SetType(nil)
				return n
			}
			u := ir.NewUnaryExpr(n.Pos(), l.BuiltinOp, arg)
			return typecheck(ir.InitExpr(n.Init(), u), top) // typecheckargs can add to old.Init

		case ir.OCOMPLEX, ir.OCOPY, ir.OUNSAFEADD, ir.OUNSAFESLICE, ir.OUNSAFESTRING:
			typecheckargs(n)
			arg1, arg2, ok := needTwoArgs(n)
			if !ok {
				n.SetType(nil)
				return n
			}
			b := ir.NewBinaryExpr(n.Pos(), l.BuiltinOp, arg1, arg2)
			return typecheck(ir.InitExpr(n.Init(), b), top) // typecheckargs can add to old.Init
		}
		panic("unreachable")
	}

	n.Fun = DefaultLit(n.Fun, nil)
	l = n.Fun
	if l.Op() == ir.OTYPE {
		if n.IsDDD {
			base.Fatalf("invalid use of ... in type conversion to %v", l.Type())
		}

		// pick off before type-checking arguments
		arg, ok := needOneArg(n, "conversion to %v", l.Type())
		if !ok {
			n.SetType(nil)
			return n
		}

		n := ir.NewConvExpr(n.Pos(), ir.OCONV, nil, arg)
		n.SetType(l.Type())
		return tcConv(n)
	}

	RewriteNonNameCall(n)
	typecheckargs(n)
	t := l.Type()
	if t == nil {
		n.SetType(nil)
		return n
	}
	types.CheckSize(t)

	switch l.Op() {
	case ir.ODOTINTER:
		n.SetOp(ir.OCALLINTER)

	case ir.ODOTMETH:
		l := l.(*ir.SelectorExpr)
		n.SetOp(ir.OCALLMETH)

		// typecheckaste was used here but there wasn't enough
		// information further down the call chain to know if we
		// were testing a method receiver for unexported fields.
		// It isn't necessary, so just do a sanity check.
		tp := t.Recv().Type

		if l.X == nil || !types.Identical(l.X.Type(), tp) {
			base.Fatalf("method receiver")
		}

	default:
		n.SetOp(ir.OCALLFUNC)
		if t.Kind() != types.TFUNC {
			if o := l; o.Name() != nil && types.BuiltinPkg.Lookup(o.Sym().Name).Def != nil {
				// be more specific when the non-function
				// name matches a predeclared function
				base.Errorf("cannot call non-function %L, declared at %s",
					l, base.FmtPos(o.Name().Pos()))
			} else {
				base.Errorf("cannot call non-function %L", l)
			}
			n.SetType(nil)
			return n
		}
	}

	typecheckaste(ir.OCALL, n.Fun, n.IsDDD, t.Params(), n.Args, func() string { return fmt.Sprintf("argument to %v", n.Fun) })
	FixVariadicCall(n)
	FixMethodCall(n)
	if t.NumResults() == 0 {
		return n
	}
	if t.NumResults() == 1 {
		n.SetType(l.Type().Result(0).Type)

		if n.Op() == ir.OCALLFUNC && n.Fun.Op() == ir.ONAME {
			if sym := n.Fun.(*ir.Name).Sym(); types.RuntimeSymName(sym) == "getg" {
				// Emit code for runtime.getg() directly instead of calling function.
				// Most such rewrites (for example the similar one for math.Sqrt) should be done in walk,
				// so that the ordering pass can make sure to preserve the semantics of the original code
				// (in particular, the exact time of the function call) by introducing temporaries.
				// In this case, we know getg() always returns the same result within a given function
				// and we want to avoid the temporaries, so we do the rewrite earlier than is typical.
				n.SetOp(ir.OGETG)
			}
		}
		return n
	}

	// multiple return
	if top&(ctxMultiOK|ctxStmt) == 0 {
		base.Errorf("multiple-value %v() in single-value context", l)
		return n
	}

	n.SetType(l.Type().ResultsTuple())
	return n
}

// tcAppend typechecks an OAPPEND node.
func tcAppend(n *ir.CallExpr) ir.Node {
	typecheckargs(n)
	args := n.Args
	if len(args) == 0 {
		base.Errorf("missing arguments to append")
		n.SetType(nil)
		return n
	}

	t := args[0].Type()
	if t == nil {
		n.SetType(nil)
		return n
	}

	n.SetType(t)
	if !t.IsSlice() {
		if ir.IsNil(args[0]) {
			base.Errorf("first argument to append must be typed slice; have untyped nil")
			n.SetType(nil)
			return n
		}

		base.Errorf("first argument to append must be slice; have %L", t)
		n.SetType(nil)
		return n
	}

	if n.IsDDD {
		if len(args) == 1 {
			base.Errorf("cannot use ... on first argument to append")
			n.SetType(nil)
			return n
		}

		if len(args) != 2 {
			base.Errorf("too many arguments to append")
			n.SetType(nil)
			return n
		}

		// AssignConv is of args[1] not required here, as the
		// types of args[0] and args[1] don't need to match
		// (They will both have an underlying type which are
		// slices of identical base types, or be []byte and string.)
		// See issue 53888.
		return n
	}

	as := args[1:]
	for i, n := range as {
		if n.Type() == nil {
			continue
		}
		as[i] = AssignConv(n, t.Elem(), "append")
		types.CheckSize(as[i].Type()) // ensure width is calculated for backend
	}
	return n
}

// tcClear typechecks an OCLEAR node.
func tcClear(n *ir.UnaryExpr) ir.Node {
	n.X = Expr(n.X)
	n.X = DefaultLit(n.X, nil)
	l := n.X
	t := l.Type()
	if t == nil {
		n.SetType(nil)
		return n
	}

	switch {
	case t.IsMap(), t.IsSlice():
	default:
		base.Errorf("invalid operation: %v (argument must be a map or slice)", n)
		n.SetType(nil)
		return n
	}

	return n
}

// tcClose typechecks an OCLOSE node.
func tcClose(n *ir.UnaryExpr) ir.Node {
	n.X = Expr(n.X)
	n.X = DefaultLit(n.X, nil)
	l := n.X
	t := l.Type()
	if t == nil {
		n.SetType(nil)
		return n
	}
	if !t.IsChan() {
		base.Errorf("invalid operation: %v (non-chan type %v)", n, t)
		n.SetType(nil)
		return n
	}

	if !t.ChanDir().CanSend() {
		base.Errorf("invalid operation: %v (cannot close receive-only channel)", n)
		n.SetType(nil)
		return n
	}
	return n
}

// tcComplex typechecks an OCOMPLEX node.
func tcComplex(n *ir.BinaryExpr) ir.Node {
	l := Expr(n.X)
	r := Expr(n.Y)
	if l.Type() == nil || r.Type() == nil {
		n.SetType(nil)
		return n
	}
	l, r = defaultlit2(l, r, false)
	if l.Type() == nil || r.Type() == nil {
		n.SetType(nil)
		return n
	}
	n.X = l
	n.Y = r

	if !types.Identical(l.Type(), r.Type()) {
		base.Errorf("invalid operation: %v (mismatched types %v and %v)", n, l.Type(), r.Type())
		n.SetType(nil)
		return n
	}

	var t *types.Type
	switch l.Type().Kind() {
	default:
		base.Errorf("invalid operation: %v (arguments have type %v, expected floating-point)", n, l.Type())
		n.SetType(nil)
		return n

	case types.TIDEAL:
		t = types.UntypedComplex

	case types.TFLOAT32:
		t = types.Types[types.TCOMPLEX64]

	case types.TFLOAT64:
		t = types.Types[types.TCOMPLEX128]
	}
	n.SetType(t)
	return n
}

// tcCopy typechecks an OCOPY node.
func tcCopy(n *ir.BinaryExpr) ir.Node {
	n.SetType(types.Types[types.TINT])
	n.X = Expr(n.X)
	n.X = DefaultLit(n.X, nil)
	n.Y = Expr(n.Y)
	n.Y = DefaultLit(n.Y, nil)
	if n.X.Type() == nil || n.Y.Type() == nil {
		n.SetType(nil)
		return n
	}

	// copy([]byte, string)
	if n.X.Type().IsSlice() && n.Y.Type().IsString() {
		if types.Identical(n.X.Type().Elem(), types.ByteType) {
			return n
		}
		base.Errorf("arguments to copy have different element types: %L and string", n.X.Type())
		n.SetType(nil)
		return n
	}

	if !n.X.Type().IsSlice() || !n.Y.Type().IsSlice() {
		if !n.X.Type().IsSlice() && !n.Y.Type().IsSlice() {
			base.Errorf("arguments to copy must be slices; have %L, %L", n.X.Type(), n.Y.Type())
		} else if !n.X.Type().IsSlice() {
			base.Errorf("first argument to copy should be slice; have %L", n.X.Type())
		} else {
			base.Errorf("second argument to copy should be slice or string; have %L", n.Y.Type())
		}
		n.SetType(nil)
		return n
	}

	if !types.Identical(n.X.Type().Elem(), n.Y.Type().Elem()) {
		base.Errorf("arguments to copy have different element types: %L and %L", n.X.Type(), n.Y.Type())
		n.SetType(nil)
		return n
	}
	return n
}

// tcDelete typechecks an ODELETE node.
func tcDelete(n *ir.CallExpr) ir.Node {
	typecheckargs(n)
	args := n.Args
	if len(args) == 0 {
		base.Errorf("missing arguments to delete")
		n.SetType(nil)
		return n
	}

	if len(args) == 1 {
		base.Errorf("missing second (key) argument to delete")
		n.SetType(nil)
		return n
	}

	if len(args) != 2 {
		base.Errorf("too many arguments to delete")
		n.SetType(nil)
		return n
	}

	l := args[0]
	r := args[1]
	if l.Type() != nil && !l.Type().IsMap() {
		base.Errorf("first argument to delete must be map; have %L", l.Type())
		n.SetType(nil)
		return n
	}

	args[1] = AssignConv(r, l.Type().Key(), "delete")
	return n
}

// tcMake typechecks an OMAKE node.
func tcMake(n *ir.CallExpr) ir.Node {
	args := n.Args
	if len(args) == 0 {
		base.Errorf("missing argument to make")
		n.SetType(nil)
		return n
	}

	n.Args = nil
	l := args[0]
	l = typecheck(l, ctxType)
	t := l.Type()
	if t == nil {
		n.SetType(nil)
		return n
	}

	i := 1
	var nn ir.Node
	switch t.Kind() {
	default:
		base.Errorf("cannot make type %v", t)
		n.SetType(nil)
		return n

	case types.TSLICE:
		if i >= len(args) {
			base.Errorf("missing len argument to make(%v)", t)
			n.SetType(nil)
			return n
		}

		l = args[i]
		i++
		l = Expr(l)
		var r ir.Node
		if i < len(args) {
			r = args[i]
			i++
			r = Expr(r)
		}

		if l.Type() == nil || (r != nil && r.Type() == nil) {
			n.SetType(nil)
			return n
		}
		if !checkmake(t, "len", &l) || r != nil && !checkmake(t, "cap", &r) {
			n.SetType(nil)
			return n
		}
		if ir.IsConst(l, constant.Int) && r != nil && ir.IsConst(r, constant.Int) && constant.Compare(l.Val(), token.GTR, r.Val()) {
			base.Errorf("len larger than cap in make(%v)", t)
			n.SetType(nil)
			return n
		}
		nn = ir.NewMakeExpr(n.Pos(), ir.OMAKESLICE, l, r)

	case types.TMAP:
		if i < len(args) {
			l = args[i]
			i++
			l = Expr(l)
			l = DefaultLit(l, types.Types[types.TINT])
			if l.Type() == nil {
				n.SetType(nil)
				return n
			}
			if !checkmake(t, "size", &l) {
				n.SetType(nil)
				return n
			}
		} else {
			l = ir.NewInt(base.Pos, 0)
		}
		nn = ir.NewMakeExpr(n.Pos(), ir.OMAKEMAP, l, nil)
		nn.SetEsc(n.Esc())

	case types.TCHAN:
		l = nil
		if i < len(args) {
			l = args[i]
			i++
			l = Expr(l)
			l = DefaultLit(l, types.Types[types.TINT])
			if l.Type() == nil {
				n.SetType(nil)
				return n
			}
			if !checkmake(t, "buffer", &l) {
				n.SetType(nil)
				return n
			}
		} else {
			l = ir.NewInt(base.Pos, 0)
		}
		nn = ir.NewMakeExpr(n.Pos(), ir.OMAKECHAN, l, nil)
	}

	if i < len(args) {
		base.Errorf("too many arguments to make(%v)", t)
		n.SetType(nil)
		return n
	}

	nn.SetType(t)
	return nn
}

// tcMakeSliceCopy typechecks an OMAKESLICECOPY node.
func tcMakeSliceCopy(n *ir.MakeExpr) ir.Node {
	// Errors here are Fatalf instead of Errorf because only the compiler
	// can construct an OMAKESLICECOPY node.
	// Components used in OMAKESCLICECOPY that are supplied by parsed source code
	// have already been typechecked in OMAKE and OCOPY earlier.
	t := n.Type()

	if t == nil {
		base.Fatalf("no type specified for OMAKESLICECOPY")
	}

	if !t.IsSlice() {
		base.Fatalf("invalid type %v for OMAKESLICECOPY", n.Type())
	}

	if n.Len == nil {
		base.Fatalf("missing len argument for OMAKESLICECOPY")
	}

	if n.Cap == nil {
		base.Fatalf("missing slice argument to copy for OMAKESLICECOPY")
	}

	n.Len = Expr(n.Len)
	n.Cap = Expr(n.Cap)

	n.Len = DefaultLit(n.Len, types.Types[types.TINT])

	if !n.Len.Type().IsInteger() && n.Type().Kind() != types.TIDEAL {
		base.Errorf("non-integer len argument in OMAKESLICECOPY")
	}

	if ir.IsConst(n.Len, constant.Int) {
		if ir.ConstOverflow(n.Len.Val(), types.Types[types.TINT]) {
			base.Fatalf("len for OMAKESLICECOPY too large")
		}
		if constant.Sign(n.Len.Val()) < 0 {
			base.Fatalf("len for OMAKESLICECOPY must be non-negative")
		}
	}
	return n
}

// tcNew typechecks an ONEW node.
func tcNew(n *ir.UnaryExpr) ir.Node {
	if n.X == nil {
		// Fatalf because the OCALL above checked for us,
		// so this must be an internally-generated mistake.
		base.Fatalf("missing argument to new")
	}
	l := n.X
	l = typecheck(l, ctxType)
	t := l.Type()
	if t == nil {
		n.SetType(nil)
		return n
	}
	n.X = l
	n.SetType(types.NewPtr(t))
	return n
}

// tcPanic typechecks an OPANIC node.
func tcPanic(n *ir.UnaryExpr) ir.Node {
	n.X = Expr(n.X)
	n.X = AssignConv(n.X, types.Types[types.TINTER], "argument to panic")
	if n.X.Type() == nil {
		n.SetType(nil)
		return n
	}
	return n
}

// tcPrint typechecks an OPRINT or OPRINTN node.
func tcPrint(n *ir.CallExpr) ir.Node {
	typecheckargs(n)
	ls := n.Args
	for i1, n1 := range ls {
		// Special case for print: int constant is int64, not int.
		if ir.IsConst(n1, constant.Int) {
			ls[i1] = DefaultLit(ls[i1], types.Types[types.TINT64])
		} else {
			ls[i1] = DefaultLit(ls[i1], nil)
		}
	}
	return n
}

// tcMinMax typechecks an OMIN or OMAX node.
func tcMinMax(n *ir.CallExpr) ir.Node {
	typecheckargs(n)
	arg0 := n.Args[0]
	for _, arg := range n.Args[1:] {
		if !types.Identical(arg.Type(), arg0.Type()) {
			base.FatalfAt(n.Pos(), "mismatched arguments: %L and %L", arg0, arg)
		}
	}
	n.SetType(arg0.Type())
	return n
}

// tcRealImag typechecks an OREAL or OIMAG node.
func tcRealImag(n *ir.UnaryExpr) ir.Node {
	n.X = Expr(n.X)
	l := n.X
	t := l.Type()
	if t == nil {
		n.SetType(nil)
		return n
	}

	// Determine result type.
	switch t.Kind() {
	case types.TIDEAL:
		n.SetType(types.UntypedFloat)
	case types.TCOMPLEX64:
		n.SetType(types.Types[types.TFLOAT32])
	case types.TCOMPLEX128:
		n.SetType(types.Types[types.TFLOAT64])
	default:
		base.Errorf("invalid argument %L for %v", l, n.Op())
		n.SetType(nil)
		return n
	}
	return n
}

// tcRecover typechecks an ORECOVER node.
func tcRecover(n *ir.CallExpr) ir.Node {
	if len(n.Args) != 0 {
		base.Errorf("too many arguments to recover")
		n.SetType(nil)
		return n
	}

	// FP is equal to caller's SP plus FixedFrameSize.
	var fp ir.Node = ir.NewCallExpr(n.Pos(), ir.OGETCALLERSP, nil, nil)
	if off := base.Ctxt.Arch.FixedFrameSize; off != 0 {
		fp = ir.NewBinaryExpr(n.Pos(), ir.OADD, fp, ir.NewInt(base.Pos, off))
	}
	// TODO(mdempsky): Replace *int32 with unsafe.Pointer, without upsetting checkptr.
	fp = ir.NewConvExpr(n.Pos(), ir.OCONVNOP, types.NewPtr(types.Types[types.TINT32]), fp)

	n.SetOp(ir.ORECOVERFP)
	n.SetType(types.Types[types.TINTER])
	n.Args = []ir.Node{Expr(fp)}
	return n
}

// tcUnsafeAdd typechecks an OUNSAFEADD node.
func tcUnsafeAdd(n *ir.BinaryExpr) *ir.BinaryExpr {
	n.X = AssignConv(Expr(n.X), types.Types[types.TUNSAFEPTR], "argument to unsafe.Add")
	n.Y = DefaultLit(Expr(n.Y), types.Types[types.TINT])
	if n.X.Type() == nil || n.Y.Type() == nil {
		n.SetType(nil)
		return n
	}
	if !n.Y.Type().IsInteger() {
		n.SetType(nil)
		return n
	}
	n.SetType(n.X.Type())
	return n
}

// tcUnsafeSlice typechecks an OUNSAFESLICE node.
func tcUnsafeSlice(n *ir.BinaryExpr) *ir.BinaryExpr {
	n.X = Expr(n.X)
	n.Y = Expr(n.Y)
	if n.X.Type() == nil || n.Y.Type() == nil {
		n.SetType(nil)
		return n
	}
	t := n.X.Type()
	if !t.IsPtr() {
		base.Errorf("first argument to unsafe.Slice must be pointer; have %L", t)
	} else if t.Elem().NotInHeap() {
		// TODO(mdempsky): This can be relaxed, but should only affect the
		// Go runtime itself. End users should only see not-in-heap
		// types due to incomplete C structs in cgo, and those types don't
		// have a meaningful size anyway.
		base.Errorf("unsafe.Slice of incomplete (or unallocatable) type not allowed")
	}

	if !checkunsafesliceorstring(n.Op(), &n.Y) {
		n.SetType(nil)
		return n
	}
	n.SetType(types.NewSlice(t.Elem()))
	return n
}

// tcUnsafeString typechecks an OUNSAFESTRING node.
func tcUnsafeString(n *ir.BinaryExpr) *ir.BinaryExpr {
	n.X = Expr(n.X)
	n.Y = Expr(n.Y)
	if n.X.Type() == nil || n.Y.Type() == nil {
		n.SetType(nil)
		return n
	}
	t := n.X.Type()
	if !t.IsPtr() || !types.Identical(t.Elem(), types.Types[types.TUINT8]) {
		base.Errorf("first argument to unsafe.String must be *byte; have %L", t)
	}

	if !checkunsafesliceorstring(n.Op(), &n.Y) {
		n.SetType(nil)
		return n
	}
	n.SetType(types.Types[types.TSTRING])
	return n
}

// ClosureStructIter iterates through a slice of closure variables returning
// their type and offset in the closure struct.
type ClosureStructIter struct {
	closureVars []*ir.Name
	offset      int64
	next        int
}

// NewClosureStructIter creates a new ClosureStructIter for closureVars.
func NewClosureStructIter(closureVars []*ir.Name) *ClosureStructIter {
	return &ClosureStructIter{
		closureVars: closureVars,
		offset:      int64(types.PtrSize), // PtrSize to skip past function entry PC field
		next:        0,
	}
}

// Next returns the next name, type and offset of the next closure variable.
// A nil name is returned after the last closure variable.
func (iter *ClosureStructIter) Next() (n *ir.Name, typ *types.Type, offset int64) {
	if iter.next >= len(iter.closureVars) {
		return nil, nil, 0
	}
	n = iter.closureVars[iter.next]
	typ = n.Type()
	if !n.Byval() {
		typ = types.NewPtr(typ)
	}
	iter.next++
	offset = types.RoundUp(iter.offset, typ.Alignment())
	iter.offset = offset + typ.Size()
	return n, typ, offset
}
```