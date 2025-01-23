Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for the *functionality* of the provided `builtins.go` code, specifically the `builtin` function within it. It also asks for examples, potential errors, and how it relates to Go's features.

2. **Identify the Core Function:** The comment at the beginning of the `builtin` function is crucial: "builtin type-checks a call to the built-in specified by id". This immediately tells us the function's primary purpose: *type checking* calls to built-in Go functions.

3. **Scan for Key Data Structures:**
    * `predeclaredFuncs`:  This is likely a map or array containing information about each built-in function (name, number of arguments, variadic status). The code uses it to get the `bin` variable.
    * `builtinId`: The `id` parameter suggests an enumeration or constant representing different built-in functions (e.g., `_Append`, `_Len`, `_Make`).
    * `Checker`:  The `check` receiver indicates this function is part of a larger type-checking system. It likely holds the current context, error reporting mechanisms, etc.
    * `operand`: The `x *operand` parameter is where the result of the built-in call will be stored. It likely contains the type and value of the expression.
    * `syntax.CallExpr`: The `call` parameter represents the abstract syntax tree node for the function call.

4. **Analyze the Control Flow (High-Level):**
    * **Initial Checks:**  The code first checks for invalid use of `...` (variadic arguments).
    * **Argument Evaluation:**  It generally evaluates arguments using `check.exprList`. However, it handles certain built-ins (like `make`, `new`) specially. This suggests these built-ins have non-standard evaluation rules.
    * **Argument Count Validation:**  The code checks if the number of provided arguments matches the expected number for the built-in.
    * **Switch Statement:** The core logic resides in a `switch id` statement. This strongly implies that the function handles each built-in function individually. This is a common pattern for processing distinct cases.

5. **Dive into the `switch` Cases (Focus on Key Examples):**
    * **`_Append`:**  Notice the specific handling for `append` with a string and `...`. This points to a special-case optimization or syntactic sugar in Go. The rest of the `_Append` case focuses on ensuring the first argument is a slice and the remaining arguments are compatible.
    * **`_Len`, `_Cap`:**  The code saves and restores `check.hasCallOrRecv`. This is a clue that `len` and `cap` can be compile-time constants in certain situations, and evaluating the argument needs to avoid triggering side effects like function calls or receives.
    * **`_Make`, `_New`:** These are explicitly handled outside the default argument evaluation. This confirms they have unique type-checking rules, particularly around the type argument itself.
    * **`_Delete`, `_Complex`, `_Real`, `_Imag`, `_Copy`:**  These cases demonstrate how the type checker enforces type constraints for different built-in functions. They involve checking argument types and ensuring compatibility.
    * **`unsafe` package built-ins (`_Add`, `_Alignof`, etc.):**  These cases deal with low-level memory operations and have stricter type requirements (e.g., `unsafe.Pointer`). The `check.verifyVersionf` calls are important, indicating version-specific features.
    * **`_Panic`, `_Print`, `_Println`, `_Recover`:** These represent built-in functions for control flow, I/O, and error handling. Their type checking is more about ensuring the arguments are of appropriate types for their specific purpose.

6. **Infer Go Feature Implementation:** Based on the analyzed cases:
    * `_Append`: Slice manipulation, variadic functions.
    * `_Len`, `_Cap`: Getting the length/capacity of collections (arrays, slices, maps, strings, channels). Compile-time evaluation of lengths/capacities for arrays.
    * `_Make`: Creating slices, maps, and channels.
    * `_New`: Allocating memory for a specific type.
    * `_Delete`: Removing elements from a map.
    * `_Complex`, `_Real`, `_Imag`: Working with complex numbers.
    * `_Copy`: Copying elements between slices.
    * `unsafe` package functions: Low-level memory operations, interacting with raw pointers.
    * `_Panic`, `_Recover`: Exception handling.
    * `_Print`, `_Println`: Basic output.

7. **Construct Examples:** Based on the inferred functionalities, create simple Go code snippets that demonstrate how these built-in functions are used. Include examples of potential errors.

8. **Identify Common Mistakes:**  Think about the type constraints and special rules observed in the code. For example, using `append` on a non-slice, incorrect argument counts for `make`, or using `len` on an invalid type.

9. **Address Command-Line Arguments:**  The code doesn't directly handle command-line arguments. This is a key point to mention. The `Checker` likely gets its configuration from other parts of the compiler.

10. **Review and Refine:** Ensure the explanation is clear, concise, and accurate. Double-check the code examples and error scenarios.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Might initially focus too much on the AST structure (`syntax.CallExpr`). Realization: The core is the *semantic* checking of the built-in functions.
* **Realization about `hasCallOrRecv`:**  Initially, might not grasp the significance. Further inspection of the `_Len` and `_Cap` cases makes it clear it's about compile-time evaluation.
* **Understanding `applyTypeFunc`:** This function is specific to type parameters and generics. Recognizing this connection is crucial.
* **Connecting `unsafe` to low-level operations:** The function names and the use of `unsafe.Pointer` make the purpose of these built-ins clear. The version checks highlight when these were introduced.

By following this structured approach of understanding the goal, identifying key components, analyzing control flow, and then focusing on specific examples, we can effectively decipher the functionality of this complex piece of code.
这段代码是 Go 语言编译器 `types2` 包中负责对内置函数调用进行类型检查的一部分。

**核心功能：**

这段代码的核心功能是 `builtin` 函数，它接收一个 `operand` 结构体用于存储结果，一个 `syntax.CallExpr` 结构体表示函数调用语法树节点，以及一个 `builtinId` 枚举值来标识具体的内置函数。`builtin` 函数的主要任务是：

1. **识别内置函数：** 通过 `builtinId` 参数确定正在调用的内置函数。
2. **检查参数：**  根据内置函数的定义，检查调用时提供的参数类型、数量和是否使用了 `...` 语法。
3. **类型推断：**  根据参数类型和内置函数的规则，推断调用结果的类型。
4. **记录类型信息：** 如果启用了类型记录，则记录内置函数的签名信息。
5. **报告错误：** 如果调用不符合类型规则，则生成相应的错误信息。

**推理 Go 语言功能的实现：**

这段代码实际上实现了 Go 语言内置函数的类型检查逻辑。Go 语言提供了一组内置函数，例如 `len`、`cap`、`make`、`append` 等，这些函数在语言层面具有特殊的含义和类型规则。`builtin` 函数就是负责确保对这些内置函数的调用符合这些规则。

**Go 代码示例：**

假设我们有以下 Go 代码：

```go
package main

func main() {
	s := []int{1, 2, 3}
	l := len(s) // 调用内置函数 len
	println(l)

	m := make(map[string]int) // 调用内置函数 make
	m["a"] = 1

	s = append(s, 4) // 调用内置函数 append
	println(s)
}
```

当 `types2` 包对这段代码进行类型检查时，对于 `len(s)`、`make(map[string]int)` 和 `append(s, 4)` 这三个内置函数调用，`builtin` 函数会被调用，并执行以下类似的操作：

**`len(s)` 的类型检查：**

* **假设输入：**
    * `id`:  `_Len` (表示 `len` 函数)
    * `call`:  表示 `len(s)` 的语法树节点
    * `x`:  一个空的 `operand` 结构体

* **代码推理：**
    1. 进入 `case _Len:` 分支。
    2. 获取参数 `s` 的类型（假设 `s` 的类型是 `[]int`，即 `Slice{elem: Typ[Int]}`）。
    3. 根据 `len` 的规则，切片的长度是 `int` 类型。
    4. 将结果类型 `Typ[Int]` 存储到 `x.typ` 中，并将 `x.mode` 设置为 `value`。

* **输出：**
    * `x.typ`: `types2.Typ[Int]`
    * `x.mode`: `value`

**`make(map[string]int)` 的类型检查：**

* **假设输入：**
    * `id`: `_Make` (表示 `make` 函数)
    * `call`: 表示 `make(map[string]int)` 的语法树节点
    * `x`: 一个空的 `operand` 结构体

* **代码推理：**
    1. 进入 `case _Make:` 分支。
    2. 获取第一个参数 `map[string]int` 的类型（`Map{key: Typ[String], elem: Typ[Int]}`）。
    3. 根据 `make` 的规则，对于 `map` 类型，至少需要一个类型参数。
    4. 检查参数数量是否正确。
    5. 将结果类型 `Map{key: Typ[String], elem: Typ[Int]}` 存储到 `x.typ` 中，并将 `x.mode` 设置为 `value`。

* **输出：**
    * `x.typ`: `types2.Map{key: types2.Typ[String], elem: types2.Typ[Int]}`
    * `x.mode`: `value`

**`append(s, 4)` 的类型检查：**

* **假设输入：**
    * `id`: `_Append` (表示 `append` 函数)
    * `call`: 表示 `append(s, 4)` 的语法树节点
    * `x`:  一个 `operand` 结构体，其 `typ` 为 `[]int`

* **代码推理：**
    1. 进入 `case _Append:` 分支。
    2. 检查第一个参数 `s` 的类型是否为切片 (`Slice{elem: Typ[Int]}`).
    3. 检查后续参数 `4` 的类型是否可以赋值给切片的元素类型 (`int`)。
    4. 根据 `append` 的规则，结果类型仍然是切片 (`[]int`)。
    5. 将结果类型 `x.typ` 保持为 `[]int`，并将 `x.mode` 设置为 `value`。

* **输出：**
    * `x.typ`: `types2.Slice{elem: types2.Typ[Int]}`
    * `x.mode`: `value`

**命令行参数的处理：**

这段代码本身不直接处理命令行参数。`types2` 包是 Go 编译器的一部分，它接收已经过词法分析和语法分析的抽象语法树 (AST) 作为输入。命令行参数的处理发生在编译器的早期阶段，例如通过 `go/parser` 包解析源代码。

**使用者易犯错的点：**

1. **`append` 的第一个参数必须是切片：**

   ```go
   var a [3]int
   // append(a, 1) // 错误：第一个参数不是切片
   s := a[:]
   append(s, 1) // 正确
   ```

2. **`make` 的参数数量和类型：**

   * 创建切片时，可以只指定长度，也可以同时指定长度和容量，但容量不能小于长度。
   * 创建 `map` 和 `chan` 时，只需要指定类型。

   ```go
   s := make([]int, 5)        // 正确
   s := make([]int, 5, 10)     // 正确
   // s := make([]int, 10, 5)  // 错误：容量小于长度
   m := make(map[string]int) // 正确
   // m := make(map[string]int, 10) // 可选的初始容量
   ```

3. **`len` 和 `cap` 的参数类型：**  只能用于支持 `len` 和 `cap` 操作的类型，例如数组、切片、字符串、`map` 和 `chan`。

   ```go
   a := [3]int{1, 2, 3}
   len(a) // 正确

   s := []int{1, 2, 3}
   len(s) // 正确

   str := "hello"
   len(str) // 正确

   m := map[string]int{"a": 1}
   len(m) // 正确

   ch := make(chan int)
   len(ch) // 正确

   // type MyInt int
   // var i MyInt
   // len(i) // 错误：MyInt 没有 len 操作
   ```

4. **`copy` 的参数必须是切片，且元素类型一致：**

   ```go
   src := []int{1, 2, 3}
   dst := make([]int, 3)
   copy(dst, src) // 正确

   srcBytes := []byte("abc")
   dstBytes := make([]byte, 3)
   copy(dstBytes, srcBytes) // 正确

   // dstFloat := make([]float64, 3)
   // copy(dstFloat, src) // 错误：元素类型不一致
   ```

5. **`delete` 的第一个参数必须是 `map`：**

   ```go
   m := map[string]int{"a": 1}
   delete(m, "a") // 正确

   // s := []int{1, 2, 3}
   // delete(s, 0) // 错误：第一个参数不是 map
   ```

6. **`close` 只能用于 `chan`，且不能是只接收的 channel：**

   ```go
   ch := make(chan int)
   close(ch) // 正确

   // roCh := make(<-chan int)
   // close(roCh) // 错误：不能关闭只接收的 channel
   ```

7. **`panic` 的参数类型可以是任意的：**

   ```go
   panic("something went wrong")
   panic(123)
   panic(struct{}{})
   ```

8. **`recover` 只能在 `defer` 函数中调用：** 虽然类型检查不会报错，但运行时行为需要注意。

9. **`unsafe` 包的函数需要谨慎使用，涉及指针操作，容易出错。** 例如，`unsafe.Pointer` 的类型转换需要理解内存布局。

这段代码通过对各种内置函数的参数进行详细的类型检查，确保了 Go 程序的类型安全性和正确性。理解这段代码有助于深入理解 Go 语言的类型系统和编译原理。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types2/builtins.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements typechecking of builtin function calls.

package types2

import (
	"cmd/compile/internal/syntax"
	"go/constant"
	"go/token"
	. "internal/types/errors"
)

// builtin type-checks a call to the built-in specified by id and
// reports whether the call is valid, with *x holding the result;
// but x.expr is not set. If the call is invalid, the result is
// false, and *x is undefined.
func (check *Checker) builtin(x *operand, call *syntax.CallExpr, id builtinId) (_ bool) {
	argList := call.ArgList

	// append is the only built-in that permits the use of ... for the last argument
	bin := predeclaredFuncs[id]
	if hasDots(call) && id != _Append {
		check.errorf(dddErrPos(call),
			InvalidDotDotDot,
			invalidOp+"invalid use of ... with built-in %s", bin.name)
		check.use(argList...)
		return
	}

	// For len(x) and cap(x) we need to know if x contains any function calls or
	// receive operations. Save/restore current setting and set hasCallOrRecv to
	// false for the evaluation of x so that we can check it afterwards.
	// Note: We must do this _before_ calling exprList because exprList evaluates
	//       all arguments.
	if id == _Len || id == _Cap {
		defer func(b bool) {
			check.hasCallOrRecv = b
		}(check.hasCallOrRecv)
		check.hasCallOrRecv = false
	}

	// Evaluate arguments for built-ins that use ordinary (value) arguments.
	// For built-ins with special argument handling (make, new, etc.),
	// evaluation is done by the respective built-in code.
	var args []*operand // not valid for _Make, _New, _Offsetof, _Trace
	var nargs int
	switch id {
	default:
		// check all arguments
		args = check.exprList(argList)
		nargs = len(args)
		for _, a := range args {
			if a.mode == invalid {
				return
			}
		}
		// first argument is always in x
		if nargs > 0 {
			*x = *args[0]
		}
	case _Make, _New, _Offsetof, _Trace:
		// arguments require special handling
		nargs = len(argList)
	}

	// check argument count
	{
		msg := ""
		if nargs < bin.nargs {
			msg = "not enough"
		} else if !bin.variadic && nargs > bin.nargs {
			msg = "too many"
		}
		if msg != "" {
			check.errorf(argErrPos(call), WrongArgCount, invalidOp+"%s arguments for %v (expected %d, found %d)", msg, call, bin.nargs, nargs)
			return
		}
	}

	switch id {
	case _Append:
		// append(s S, x ...T) S, where T is the element type of S
		// spec: "The variadic function append appends zero or more values x to s of type
		// S, which must be a slice type, and returns the resulting slice, also of type S.
		// The values x are passed to a parameter of type ...T where T is the element type
		// of S and the respective parameter passing rules apply."
		S := x.typ
		var T Type
		if s, _ := coreType(S).(*Slice); s != nil {
			T = s.elem
		} else {
			var cause string
			switch {
			case x.isNil():
				cause = "have untyped nil"
			case isTypeParam(S):
				if u := coreType(S); u != nil {
					cause = check.sprintf("%s has core type %s", x, u)
				} else {
					cause = check.sprintf("%s has no core type", x)
				}
			default:
				cause = check.sprintf("have %s", x)
			}
			// don't use invalidArg prefix here as it would repeat "argument" in the error message
			check.errorf(x, InvalidAppend, "first argument to append must be a slice; %s", cause)
			return
		}

		// spec: "As a special case, append also accepts a first argument assignable
		// to type []byte with a second argument of string type followed by ... .
		// This form appends the bytes of the string.
		if nargs == 2 && hasDots(call) {
			if ok, _ := x.assignableTo(check, NewSlice(universeByte), nil); ok {
				y := args[1]
				if t := coreString(y.typ); t != nil && isString(t) {
					if check.recordTypes() {
						sig := makeSig(S, S, y.typ)
						sig.variadic = true
						check.recordBuiltinType(call.Fun, sig)
					}
					x.mode = value
					x.typ = S
					break
				}
			}
		}

		// check general case by creating custom signature
		sig := makeSig(S, S, NewSlice(T)) // []T required for variadic signature
		sig.variadic = true
		check.arguments(call, sig, nil, nil, args, nil, nil) // discard result (we know the result type)
		// ok to continue even if check.arguments reported errors

		x.mode = value
		x.typ = S
		if check.recordTypes() {
			check.recordBuiltinType(call.Fun, sig)
		}

	case _Cap, _Len:
		// cap(x)
		// len(x)
		mode := invalid
		var val constant.Value
		switch t := arrayPtrDeref(under(x.typ)).(type) {
		case *Basic:
			if isString(t) && id == _Len {
				if x.mode == constant_ {
					mode = constant_
					val = constant.MakeInt64(int64(len(constant.StringVal(x.val))))
				} else {
					mode = value
				}
			}

		case *Array:
			mode = value
			// spec: "The expressions len(s) and cap(s) are constants
			// if the type of s is an array or pointer to an array and
			// the expression s does not contain channel receives or
			// function calls; in this case s is not evaluated."
			if !check.hasCallOrRecv {
				mode = constant_
				if t.len >= 0 {
					val = constant.MakeInt64(t.len)
				} else {
					val = constant.MakeUnknown()
				}
			}

		case *Slice, *Chan:
			mode = value

		case *Map:
			if id == _Len {
				mode = value
			}

		case *Interface:
			if !isTypeParam(x.typ) {
				break
			}
			if underIs(x.typ, func(u Type) bool {
				switch t := arrayPtrDeref(u).(type) {
				case *Basic:
					if isString(t) && id == _Len {
						return true
					}
				case *Array, *Slice, *Chan:
					return true
				case *Map:
					if id == _Len {
						return true
					}
				}
				return false
			}) {
				mode = value
			}
		}

		if mode == invalid {
			// avoid error if underlying type is invalid
			if isValid(under(x.typ)) {
				code := InvalidCap
				if id == _Len {
					code = InvalidLen
				}
				check.errorf(x, code, invalidArg+"%s for built-in %s", x, bin.name)
			}
			return
		}

		// record the signature before changing x.typ
		if check.recordTypes() && mode != constant_ {
			check.recordBuiltinType(call.Fun, makeSig(Typ[Int], x.typ))
		}

		x.mode = mode
		x.typ = Typ[Int]
		x.val = val

	case _Clear:
		// clear(m)
		check.verifyVersionf(call.Fun, go1_21, "clear")

		if !underIs(x.typ, func(u Type) bool {
			switch u.(type) {
			case *Map, *Slice:
				return true
			}
			check.errorf(x, InvalidClear, invalidArg+"cannot clear %s: argument must be (or constrained by) map or slice", x)
			return false
		}) {
			return
		}

		x.mode = novalue
		if check.recordTypes() {
			check.recordBuiltinType(call.Fun, makeSig(nil, x.typ))
		}

	case _Close:
		// close(c)
		if !underIs(x.typ, func(u Type) bool {
			uch, _ := u.(*Chan)
			if uch == nil {
				check.errorf(x, InvalidClose, invalidOp+"cannot close non-channel %s", x)
				return false
			}
			if uch.dir == RecvOnly {
				check.errorf(x, InvalidClose, invalidOp+"cannot close receive-only channel %s", x)
				return false
			}
			return true
		}) {
			return
		}
		x.mode = novalue
		if check.recordTypes() {
			check.recordBuiltinType(call.Fun, makeSig(nil, x.typ))
		}

	case _Complex:
		// complex(x, y floatT) complexT
		y := args[1]

		// convert or check untyped arguments
		d := 0
		if isUntyped(x.typ) {
			d |= 1
		}
		if isUntyped(y.typ) {
			d |= 2
		}
		switch d {
		case 0:
			// x and y are typed => nothing to do
		case 1:
			// only x is untyped => convert to type of y
			check.convertUntyped(x, y.typ)
		case 2:
			// only y is untyped => convert to type of x
			check.convertUntyped(y, x.typ)
		case 3:
			// x and y are untyped =>
			// 1) if both are constants, convert them to untyped
			//    floating-point numbers if possible,
			// 2) if one of them is not constant (possible because
			//    it contains a shift that is yet untyped), convert
			//    both of them to float64 since they must have the
			//    same type to succeed (this will result in an error
			//    because shifts of floats are not permitted)
			if x.mode == constant_ && y.mode == constant_ {
				toFloat := func(x *operand) {
					if isNumeric(x.typ) && constant.Sign(constant.Imag(x.val)) == 0 {
						x.typ = Typ[UntypedFloat]
					}
				}
				toFloat(x)
				toFloat(y)
			} else {
				check.convertUntyped(x, Typ[Float64])
				check.convertUntyped(y, Typ[Float64])
				// x and y should be invalid now, but be conservative
				// and check below
			}
		}
		if x.mode == invalid || y.mode == invalid {
			return
		}

		// both argument types must be identical
		if !Identical(x.typ, y.typ) {
			check.errorf(x, InvalidComplex, invalidOp+"%v (mismatched types %s and %s)", call, x.typ, y.typ)
			return
		}

		// the argument types must be of floating-point type
		// (applyTypeFunc never calls f with a type parameter)
		f := func(typ Type) Type {
			assert(!isTypeParam(typ))
			if t, _ := under(typ).(*Basic); t != nil {
				switch t.kind {
				case Float32:
					return Typ[Complex64]
				case Float64:
					return Typ[Complex128]
				case UntypedFloat:
					return Typ[UntypedComplex]
				}
			}
			return nil
		}
		resTyp := check.applyTypeFunc(f, x, id)
		if resTyp == nil {
			check.errorf(x, InvalidComplex, invalidArg+"arguments have type %s, expected floating-point", x.typ)
			return
		}

		// if both arguments are constants, the result is a constant
		if x.mode == constant_ && y.mode == constant_ {
			x.val = constant.BinaryOp(constant.ToFloat(x.val), token.ADD, constant.MakeImag(constant.ToFloat(y.val)))
		} else {
			x.mode = value
		}

		if check.recordTypes() && x.mode != constant_ {
			check.recordBuiltinType(call.Fun, makeSig(resTyp, x.typ, x.typ))
		}

		x.typ = resTyp

	case _Copy:
		// copy(x, y []T) int
		dst, _ := coreType(x.typ).(*Slice)

		y := args[1]
		src0 := coreString(y.typ)
		if src0 != nil && isString(src0) {
			src0 = NewSlice(universeByte)
		}
		src, _ := src0.(*Slice)

		if dst == nil || src == nil {
			check.errorf(x, InvalidCopy, invalidArg+"copy expects slice arguments; found %s and %s", x, y)
			return
		}

		if !Identical(dst.elem, src.elem) {
			check.errorf(x, InvalidCopy, invalidArg+"arguments to copy %s and %s have different element types %s and %s", x, y, dst.elem, src.elem)
			return
		}

		if check.recordTypes() {
			check.recordBuiltinType(call.Fun, makeSig(Typ[Int], x.typ, y.typ))
		}
		x.mode = value
		x.typ = Typ[Int]

	case _Delete:
		// delete(map_, key)
		// map_ must be a map type or a type parameter describing map types.
		// The key cannot be a type parameter for now.
		map_ := x.typ
		var key Type
		if !underIs(map_, func(u Type) bool {
			map_, _ := u.(*Map)
			if map_ == nil {
				check.errorf(x, InvalidDelete, invalidArg+"%s is not a map", x)
				return false
			}
			if key != nil && !Identical(map_.key, key) {
				check.errorf(x, InvalidDelete, invalidArg+"maps of %s must have identical key types", x)
				return false
			}
			key = map_.key
			return true
		}) {
			return
		}

		*x = *args[1] // key
		check.assignment(x, key, "argument to delete")
		if x.mode == invalid {
			return
		}

		x.mode = novalue
		if check.recordTypes() {
			check.recordBuiltinType(call.Fun, makeSig(nil, map_, key))
		}

	case _Imag, _Real:
		// imag(complexT) floatT
		// real(complexT) floatT

		// convert or check untyped argument
		if isUntyped(x.typ) {
			if x.mode == constant_ {
				// an untyped constant number can always be considered
				// as a complex constant
				if isNumeric(x.typ) {
					x.typ = Typ[UntypedComplex]
				}
			} else {
				// an untyped non-constant argument may appear if
				// it contains a (yet untyped non-constant) shift
				// expression: convert it to complex128 which will
				// result in an error (shift of complex value)
				check.convertUntyped(x, Typ[Complex128])
				// x should be invalid now, but be conservative and check
				if x.mode == invalid {
					return
				}
			}
		}

		// the argument must be of complex type
		// (applyTypeFunc never calls f with a type parameter)
		f := func(typ Type) Type {
			assert(!isTypeParam(typ))
			if t, _ := under(typ).(*Basic); t != nil {
				switch t.kind {
				case Complex64:
					return Typ[Float32]
				case Complex128:
					return Typ[Float64]
				case UntypedComplex:
					return Typ[UntypedFloat]
				}
			}
			return nil
		}
		resTyp := check.applyTypeFunc(f, x, id)
		if resTyp == nil {
			code := InvalidImag
			if id == _Real {
				code = InvalidReal
			}
			check.errorf(x, code, invalidArg+"argument has type %s, expected complex type", x.typ)
			return
		}

		// if the argument is a constant, the result is a constant
		if x.mode == constant_ {
			if id == _Real {
				x.val = constant.Real(x.val)
			} else {
				x.val = constant.Imag(x.val)
			}
		} else {
			x.mode = value
		}

		if check.recordTypes() && x.mode != constant_ {
			check.recordBuiltinType(call.Fun, makeSig(resTyp, x.typ))
		}

		x.typ = resTyp

	case _Make:
		// make(T, n)
		// make(T, n, m)
		// (no argument evaluated yet)
		arg0 := argList[0]
		T := check.varType(arg0)
		if !isValid(T) {
			return
		}

		var min int // minimum number of arguments
		switch coreType(T).(type) {
		case *Slice:
			min = 2
		case *Map, *Chan:
			min = 1
		case nil:
			check.errorf(arg0, InvalidMake, invalidArg+"cannot make %s: no core type", arg0)
			return
		default:
			check.errorf(arg0, InvalidMake, invalidArg+"cannot make %s; type must be slice, map, or channel", arg0)
			return
		}
		if nargs < min || min+1 < nargs {
			check.errorf(call, WrongArgCount, invalidOp+"%v expects %d or %d arguments; found %d", call, min, min+1, nargs)
			return
		}

		types := []Type{T}
		var sizes []int64 // constant integer arguments, if any
		for _, arg := range argList[1:] {
			typ, size := check.index(arg, -1) // ok to continue with typ == Typ[Invalid]
			types = append(types, typ)
			if size >= 0 {
				sizes = append(sizes, size)
			}
		}
		if len(sizes) == 2 && sizes[0] > sizes[1] {
			check.error(argList[1], SwappedMakeArgs, invalidArg+"length and capacity swapped")
			// safe to continue
		}
		x.mode = value
		x.typ = T
		if check.recordTypes() {
			check.recordBuiltinType(call.Fun, makeSig(x.typ, types...))
		}

	case _Max, _Min:
		// max(x, ...)
		// min(x, ...)
		check.verifyVersionf(call.Fun, go1_21, "built-in %s", bin.name)

		op := token.LSS
		if id == _Max {
			op = token.GTR
		}

		for i, a := range args {
			if a.mode == invalid {
				return
			}

			if !allOrdered(a.typ) {
				check.errorf(a, InvalidMinMaxOperand, invalidArg+"%s cannot be ordered", a)
				return
			}

			// The first argument is already in x and there's nothing left to do.
			if i > 0 {
				check.matchTypes(x, a)
				if x.mode == invalid {
					return
				}

				if !Identical(x.typ, a.typ) {
					check.errorf(a, MismatchedTypes, invalidArg+"mismatched types %s (previous argument) and %s (type of %s)", x.typ, a.typ, a.expr)
					return
				}

				if x.mode == constant_ && a.mode == constant_ {
					if constant.Compare(a.val, op, x.val) {
						*x = *a
					}
				} else {
					x.mode = value
				}
			}
		}

		// If nargs == 1, make sure x.mode is either a value or a constant.
		if x.mode != constant_ {
			x.mode = value
			// A value must not be untyped.
			check.assignment(x, &emptyInterface, "argument to built-in "+bin.name)
			if x.mode == invalid {
				return
			}
		}

		// Use the final type computed above for all arguments.
		for _, a := range args {
			check.updateExprType(a.expr, x.typ, true)
		}

		if check.recordTypes() && x.mode != constant_ {
			types := make([]Type, nargs)
			for i := range types {
				types[i] = x.typ
			}
			check.recordBuiltinType(call.Fun, makeSig(x.typ, types...))
		}

	case _New:
		// new(T)
		// (no argument evaluated yet)
		T := check.varType(argList[0])
		if !isValid(T) {
			return
		}

		x.mode = value
		x.typ = &Pointer{base: T}
		if check.recordTypes() {
			check.recordBuiltinType(call.Fun, makeSig(x.typ, T))
		}

	case _Panic:
		// panic(x)
		// record panic call if inside a function with result parameters
		// (for use in Checker.isTerminating)
		if check.sig != nil && check.sig.results.Len() > 0 {
			// function has result parameters
			p := check.isPanic
			if p == nil {
				// allocate lazily
				p = make(map[*syntax.CallExpr]bool)
				check.isPanic = p
			}
			p[call] = true
		}

		check.assignment(x, &emptyInterface, "argument to panic")
		if x.mode == invalid {
			return
		}

		x.mode = novalue
		if check.recordTypes() {
			check.recordBuiltinType(call.Fun, makeSig(nil, &emptyInterface))
		}

	case _Print, _Println:
		// print(x, y, ...)
		// println(x, y, ...)
		var params []Type
		if nargs > 0 {
			params = make([]Type, nargs)
			for i, a := range args {
				check.assignment(a, nil, "argument to built-in "+predeclaredFuncs[id].name)
				if a.mode == invalid {
					return
				}
				params[i] = a.typ
			}
		}

		x.mode = novalue
		if check.recordTypes() {
			check.recordBuiltinType(call.Fun, makeSig(nil, params...))
		}

	case _Recover:
		// recover() interface{}
		x.mode = value
		x.typ = &emptyInterface
		if check.recordTypes() {
			check.recordBuiltinType(call.Fun, makeSig(x.typ))
		}

	case _Add:
		// unsafe.Add(ptr unsafe.Pointer, len IntegerType) unsafe.Pointer
		check.verifyVersionf(call.Fun, go1_17, "unsafe.Add")

		check.assignment(x, Typ[UnsafePointer], "argument to unsafe.Add")
		if x.mode == invalid {
			return
		}

		y := args[1]
		if !check.isValidIndex(y, InvalidUnsafeAdd, "length", true) {
			return
		}

		x.mode = value
		x.typ = Typ[UnsafePointer]
		if check.recordTypes() {
			check.recordBuiltinType(call.Fun, makeSig(x.typ, x.typ, y.typ))
		}

	case _Alignof:
		// unsafe.Alignof(x T) uintptr
		check.assignment(x, nil, "argument to unsafe.Alignof")
		if x.mode == invalid {
			return
		}

		if hasVarSize(x.typ, nil) {
			x.mode = value
			if check.recordTypes() {
				check.recordBuiltinType(call.Fun, makeSig(Typ[Uintptr], x.typ))
			}
		} else {
			x.mode = constant_
			x.val = constant.MakeInt64(check.conf.alignof(x.typ))
			// result is constant - no need to record signature
		}
		x.typ = Typ[Uintptr]

	case _Offsetof:
		// unsafe.Offsetof(x T) uintptr, where x must be a selector
		// (no argument evaluated yet)
		arg0 := argList[0]
		selx, _ := syntax.Unparen(arg0).(*syntax.SelectorExpr)
		if selx == nil {
			check.errorf(arg0, BadOffsetofSyntax, invalidArg+"%s is not a selector expression", arg0)
			check.use(arg0)
			return
		}

		check.expr(nil, x, selx.X)
		if x.mode == invalid {
			return
		}

		base := derefStructPtr(x.typ)
		sel := selx.Sel.Value
		obj, index, indirect := lookupFieldOrMethod(base, false, check.pkg, sel, false)
		switch obj.(type) {
		case nil:
			check.errorf(x, MissingFieldOrMethod, invalidArg+"%s has no single field %s", base, sel)
			return
		case *Func:
			// TODO(gri) Using derefStructPtr may result in methods being found
			// that don't actually exist. An error either way, but the error
			// message is confusing. See: https://play.golang.org/p/al75v23kUy ,
			// but go/types reports: "invalid argument: x.m is a method value".
			check.errorf(arg0, InvalidOffsetof, invalidArg+"%s is a method value", arg0)
			return
		}
		if indirect {
			check.errorf(x, InvalidOffsetof, invalidArg+"field %s is embedded via a pointer in %s", sel, base)
			return
		}

		// TODO(gri) Should we pass x.typ instead of base (and have indirect report if derefStructPtr indirected)?
		check.recordSelection(selx, FieldVal, base, obj, index, false)

		// record the selector expression (was bug - go.dev/issue/47895)
		{
			mode := value
			if x.mode == variable || indirect {
				mode = variable
			}
			check.record(&operand{mode, selx, obj.Type(), nil, 0})
		}

		// The field offset is considered a variable even if the field is declared before
		// the part of the struct which is variable-sized. This makes both the rules
		// simpler and also permits (or at least doesn't prevent) a compiler from re-
		// arranging struct fields if it wanted to.
		if hasVarSize(base, nil) {
			x.mode = value
			if check.recordTypes() {
				check.recordBuiltinType(call.Fun, makeSig(Typ[Uintptr], obj.Type()))
			}
		} else {
			offs := check.conf.offsetof(base, index)
			if offs < 0 {
				check.errorf(x, TypeTooLarge, "%s is too large", x)
				return
			}
			x.mode = constant_
			x.val = constant.MakeInt64(offs)
			// result is constant - no need to record signature
		}
		x.typ = Typ[Uintptr]

	case _Sizeof:
		// unsafe.Sizeof(x T) uintptr
		check.assignment(x, nil, "argument to unsafe.Sizeof")
		if x.mode == invalid {
			return
		}

		if hasVarSize(x.typ, nil) {
			x.mode = value
			if check.recordTypes() {
				check.recordBuiltinType(call.Fun, makeSig(Typ[Uintptr], x.typ))
			}
		} else {
			size := check.conf.sizeof(x.typ)
			if size < 0 {
				check.errorf(x, TypeTooLarge, "%s is too large", x)
				return
			}
			x.mode = constant_
			x.val = constant.MakeInt64(size)
			// result is constant - no need to record signature
		}
		x.typ = Typ[Uintptr]

	case _Slice:
		// unsafe.Slice(ptr *T, len IntegerType) []T
		check.verifyVersionf(call.Fun, go1_17, "unsafe.Slice")

		ptr, _ := coreType(x.typ).(*Pointer)
		if ptr == nil {
			check.errorf(x, InvalidUnsafeSlice, invalidArg+"%s is not a pointer", x)
			return
		}

		y := args[1]
		if !check.isValidIndex(y, InvalidUnsafeSlice, "length", false) {
			return
		}

		x.mode = value
		x.typ = NewSlice(ptr.base)
		if check.recordTypes() {
			check.recordBuiltinType(call.Fun, makeSig(x.typ, ptr, y.typ))
		}

	case _SliceData:
		// unsafe.SliceData(slice []T) *T
		check.verifyVersionf(call.Fun, go1_20, "unsafe.SliceData")

		slice, _ := coreType(x.typ).(*Slice)
		if slice == nil {
			check.errorf(x, InvalidUnsafeSliceData, invalidArg+"%s is not a slice", x)
			return
		}

		x.mode = value
		x.typ = NewPointer(slice.elem)
		if check.recordTypes() {
			check.recordBuiltinType(call.Fun, makeSig(x.typ, slice))
		}

	case _String:
		// unsafe.String(ptr *byte, len IntegerType) string
		check.verifyVersionf(call.Fun, go1_20, "unsafe.String")

		check.assignment(x, NewPointer(universeByte), "argument to unsafe.String")
		if x.mode == invalid {
			return
		}

		y := args[1]
		if !check.isValidIndex(y, InvalidUnsafeString, "length", false) {
			return
		}

		x.mode = value
		x.typ = Typ[String]
		if check.recordTypes() {
			check.recordBuiltinType(call.Fun, makeSig(x.typ, NewPointer(universeByte), y.typ))
		}

	case _StringData:
		// unsafe.StringData(str string) *byte
		check.verifyVersionf(call.Fun, go1_20, "unsafe.StringData")

		check.assignment(x, Typ[String], "argument to unsafe.StringData")
		if x.mode == invalid {
			return
		}

		x.mode = value
		x.typ = NewPointer(universeByte)
		if check.recordTypes() {
			check.recordBuiltinType(call.Fun, makeSig(x.typ, Typ[String]))
		}

	case _Assert:
		// assert(pred) causes a typechecker error if pred is false.
		// The result of assert is the value of pred if there is no error.
		// Note: assert is only available in self-test mode.
		if x.mode != constant_ || !isBoolean(x.typ) {
			check.errorf(x, Test, invalidArg+"%s is not a boolean constant", x)
			return
		}
		if x.val.Kind() != constant.Bool {
			check.errorf(x, Test, "internal error: value of %s should be a boolean constant", x)
			return
		}
		if !constant.BoolVal(x.val) {
			check.errorf(call, Test, "%v failed", call)
			// compile-time assertion failure - safe to continue
		}
		// result is constant - no need to record signature

	case _Trace:
		// trace(x, y, z, ...) dumps the positions, expressions, and
		// values of its arguments. The result of trace is the value
		// of the first argument.
		// Note: trace is only available in self-test mode.
		// (no argument evaluated yet)
		if nargs == 0 {
			check.dump("%v: trace() without arguments", atPos(call))
			x.mode = novalue
			break
		}
		var t operand
		x1 := x
		for _, arg := range argList {
			check.rawExpr(nil, x1, arg, nil, false) // permit trace for types, e.g.: new(trace(T))
			check.dump("%v: %s", atPos(x1), x1)
			x1 = &t // use incoming x only for first argument
		}
		if x.mode == invalid {
			return
		}
		// trace is only available in test mode - no need to record signature

	default:
		panic("unreachable")
	}

	assert(x.mode != invalid)
	return true
}

// hasVarSize reports if the size of type t is variable due to type parameters
// or if the type is infinitely-sized due to a cycle for which the type has not
// yet been checked.
func hasVarSize(t Type, seen map[*Named]bool) (varSized bool) {
	// Cycles are only possible through *Named types.
	// The seen map is used to detect cycles and track
	// the results of previously seen types.
	if named := asNamed(t); named != nil {
		if v, ok := seen[named]; ok {
			return v
		}
		if seen == nil {
			seen = make(map[*Named]bool)
		}
		seen[named] = true // possibly cyclic until proven otherwise
		defer func() {
			seen[named] = varSized // record final determination for named
		}()
	}

	switch u := under(t).(type) {
	case *Array:
		return hasVarSize(u.elem, seen)
	case *Struct:
		for _, f := range u.fields {
			if hasVarSize(f.typ, seen) {
				return true
			}
		}
	case *Interface:
		return isTypeParam(t)
	case *Named, *Union:
		panic("unreachable")
	}
	return false
}

// applyTypeFunc applies f to x. If x is a type parameter,
// the result is a type parameter constrained by a new
// interface bound. The type bounds for that interface
// are computed by applying f to each of the type bounds
// of x. If any of these applications of f return nil,
// applyTypeFunc returns nil.
// If x is not a type parameter, the result is f(x).
func (check *Checker) applyTypeFunc(f func(Type) Type, x *operand, id builtinId) Type {
	if tp, _ := Unalias(x.typ).(*TypeParam); tp != nil {
		// Test if t satisfies the requirements for the argument
		// type and collect possible result types at the same time.
		var terms []*Term
		if !tp.is(func(t *term) bool {
			if t == nil {
				return false
			}
			if r := f(t.typ); r != nil {
				terms = append(terms, NewTerm(t.tilde, r))
				return true
			}
			return false
		}) {
			return nil
		}

		// We can type-check this fine but we're introducing a synthetic
		// type parameter for the result. It's not clear what the API
		// implications are here. Report an error for 1.18 (see go.dev/issue/50912),
		// but continue type-checking.
		var code Code
		switch id {
		case _Real:
			code = InvalidReal
		case _Imag:
			code = InvalidImag
		case _Complex:
			code = InvalidComplex
		default:
			panic("unreachable")
		}
		check.softErrorf(x, code, "%s not supported as argument to built-in %s for go1.18 (see go.dev/issue/50937)", x, predeclaredFuncs[id].name)

		// Construct a suitable new type parameter for the result type.
		// The type parameter is placed in the current package so export/import
		// works as expected.
		tpar := NewTypeName(nopos, check.pkg, tp.obj.name, nil)
		ptyp := check.newTypeParam(tpar, NewInterfaceType(nil, []Type{NewUnion(terms)})) // assigns type to tpar as a side-effect
		ptyp.index = tp.index

		return ptyp
	}

	return f(x.typ)
}

// makeSig makes a signature for the given argument and result types.
// Default types are used for untyped arguments, and res may be nil.
func makeSig(res Type, args ...Type) *Signature {
	list := make([]*Var, len(args))
	for i, param := range args {
		list[i] = NewVar(nopos, nil, "", Default(param))
	}
	params := NewTuple(list...)
	var result *Tuple
	if res != nil {
		assert(!isUntyped(res))
		result = NewTuple(NewVar(nopos, nil, "", res))
	}
	return &Signature{params: params, results: result}
}

// arrayPtrDeref returns A if typ is of the form *A and A is an array;
// otherwise it returns typ.
func arrayPtrDeref(typ Type) Type {
	if p, ok := Unalias(typ).(*Pointer); ok {
		if a, _ := under(p.base).(*Array); a != nil {
			return a
		}
	}
	return typ
}
```