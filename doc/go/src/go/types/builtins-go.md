Response:
我的思考过程如下：

1. **理解目标：** 目标是分析 `go/src/go/types/builtins.go` 文件的部分代码，列举其功能，并尽可能推断出它是 Go 语言哪个功能的实现。  需要提供代码示例、假设的输入输出、命令行参数处理（如果有）、以及常见的错误用法。

2. **初步观察：** 代码注释明确指出 "This file implements typechecking of builtin function calls."  核心函数是 `builtin`。这基本确定了它的主要职责是对 Go 内置函数的调用进行类型检查。

3. **深入 `builtin` 函数：**  仔细阅读 `builtin` 函数的逻辑，可以发现它处理了各种内置函数，例如 `append`、`len`、`cap`、`make`、`new`、`panic`、`print`、`println`，以及 `unsafe` 包中的函数，例如 `Alignof`、`Sizeof`、`Offsetof` 等。

4. **功能拆解：**  基于 `builtin` 函数的 `switch` 结构和针对不同 `id` 的处理，可以将文件功能分解为：
    * **参数数量检查：**  检查内置函数调用的参数数量是否正确。
    * **类型检查：**  根据内置函数的签名，检查参数的类型是否匹配。
    * **特殊处理：**  针对某些内置函数（例如 `append`、`make`、`new`），进行特殊的参数处理和类型推断。
    * **常量计算：**  对于 `len`、`cap`、`unsafe.Alignof`、`unsafe.Sizeof`、`unsafe.Offsetof` 等在编译时可以确定的内置函数调用，尝试计算常量结果。
    * **版本控制：**  使用 `check.verifyVersionf` 来限制某些内置函数（例如 `clear`、`max`、`min`、`unsafe` 包的函数）的最低 Go 版本。
    * **错误报告：**  如果类型检查失败，则生成相应的错误信息。
    * **类型记录：**  在 `check.recordTypes()` 条件下，记录内置函数的签名。
    * **`unsafe` 包支持：**  专门处理 `unsafe` 包中的函数，这些函数允许执行一些“不安全”的操作，例如直接操作内存地址。
    * **测试支持：** 包含 `assert` 和 `trace` 这样的内置函数，这些函数主要用于类型检查器的自测。

5. **核心功能的推断：** 结合代码和注释，可以推断出此文件是 Go 语言**类型检查器**的一部分，专门负责处理内置函数的调用。 类型检查是编译过程中的重要环节，用于确保代码的类型安全。

6. **代码示例：**  针对一些关键的内置函数，编写 Go 代码示例，并提供假设的输入和输出，以展示类型检查器是如何工作的。  例如，针对 `len` 和 `append` 提供例子，展示参数类型正确和错误的情况。

7. **命令行参数处理：**  浏览代码，没有发现直接处理命令行参数的逻辑。因此，可以得出结论，此文件本身不直接处理命令行参数。它的行为受到 Go 编译器（`go build` 或 `go run`）的控制。

8. **易犯错误点：**  根据对代码的理解，列举使用内置函数时容易犯的错误，例如 `append` 的第一个参数必须是切片，`len` 和 `cap` 的参数类型限制，以及 `make` 的参数数量和类型限制。

9. **组织答案：**  将以上分析和示例组织成结构化的中文答案，确保内容清晰、易懂，并覆盖了问题的所有要求。

10. **自我审视和完善：**  回顾答案，检查是否有遗漏或不准确的地方，例如，最初可能忽略了对 `unsafe` 包的处理，或者对版本控制的理解不够深入。  对答案进行必要的修正和补充。  例如，补充了对 `unsafe` 包函数的说明，并强调了版本控制的重要性。  同时，添加了关于 `assert` 和 `trace` 仅在测试模式下可用的说明。

通过以上步骤，可以系统地分析给定的 Go 源代码片段，并生成满足问题要求的详细解答。

这段代码是 Go 语言类型检查器 (`go/types`) 中处理内置函数调用的核心部分。它定义了 `Checker` 结构体的一个方法 `builtin`，用于对 Go 语言的内置函数（例如 `len`, `cap`, `make`, `append` 等）的调用进行类型检查。

**功能列表:**

1. **识别内置函数:**  通过 `builtinId` 枚举类型（在 `predeclaredFuncs` 数组中查找）来确定被调用的具体内置函数。
2. **检查 `...` 用法:**  除了 `append`，其他内置函数调用中如果使用了 `...` (变长参数)，会报错。
3. **处理 `len` 和 `cap` 的特殊情况:** 在处理 `len(x)` 和 `cap(x)` 时，会临时禁用调用或接收操作的检查，以便正确判断 `x` 是否可以在编译时求值。
4. **评估参数:**  对于大多数内置函数，会先评估它们的参数表达式的类型和值。对于 `make`, `new`, `offsetof`, `trace` 等内置函数，参数有特殊的处理逻辑。
5. **检查参数数量:**  根据内置函数的定义 (`bin.nargs` 和 `bin.variadic`) 检查调用时提供的参数数量是否正确。
6. **针对不同内置函数进行类型检查:**  使用 `switch` 语句针对不同的内置函数执行特定的类型检查逻辑。例如：
    * **`append`:** 检查第一个参数是否是切片，后续参数是否可以添加到切片中。支持 `append([]byte, string...)` 的特殊形式。
    * **`len`, `cap`:** 检查参数是否是支持 `len` 或 `cap` 操作的类型（数组、切片、字符串、channel、map）。如果参数是常量，且不包含 channel 接收或函数调用，则结果也是常量。
    * **`make`:** 检查 `make` 的第一个参数是否是切片、map 或 channel 类型，并检查后续的长度和容量参数是否为整数。
    * **`new`:** 检查 `new` 的参数是否是类型。
    * **`delete`:** 检查第一个参数是否是 map 类型，第二个参数的类型是否与 map 的键类型匹配。
    * **`complex`, `real`, `imag`:** 检查参数是否是数字类型，并根据参数类型返回相应的复数或浮点数类型。
    * **`copy`:** 检查两个参数是否都是切片，且元素类型相同。
    * **`panic`:** 记录 `panic` 调用，用于后续的终止分析。
    * **`print`, `println`:** 允许任意类型的参数。
    * **`recover`:** 返回 `interface{}` 类型。
    * **`unsafe` 包的函数 (`Add`, `Alignof`, `Offsetof`, `Sizeof`, `Slice`, `SliceData`, `String`, `StringData`):**  检查参数类型是否符合 `unsafe` 包函数的签名。这些函数通常涉及指针和内存操作。
    * **`clear`:** 检查参数是否为 map 或 slice 类型 (Go 1.21 新增)。
    * **`min`, `max`:** 检查参数是否可排序 (Go 1.21 新增)。
    * **`assert`, `trace`:**  用于类型检查器的自测。
7. **记录类型信息:**  如果开启了类型记录 (`check.recordTypes()`)，会记录内置函数的签名。
8. **设置结果 `operand`:**  如果调用有效，会将结果类型和模式（例如 `value`, `constant_`, `novalue`) 存储在 `operand` 结构体 `x` 中。

**它是什么Go语言功能的实现:**

这段代码是 Go 语言**内置函数类型检查**功能的实现。类型检查是 Go 编译器前端的一个关键步骤，它确保程序中的类型使用是安全的和符合 Go 语言规范的。对于内置函数，由于其行为比较特殊，不能像普通函数一样进行类型检查，因此需要单独的逻辑来处理。

**Go 代码举例说明:**

```go
package main

func main() {
	s := make([]int, 5)
	l := len(s) // 类型检查器会检查 len 的参数是否是支持 len 操作的类型 (slice)
	println(l)

	m := make(map[string]int)
	delete(m, "key") // 类型检查器会检查 delete 的第一个参数是否是 map，第二个参数类型是否与 map 的键类型匹配

	str := "hello"
	// append(str, "world") // 假设的错误用法，类型检查器会报错，因为 append 的第一个参数必须是 slice
	slice := []byte(str)
	slice = append(slice, '!') // 类型检查器允许这种用法

	i := 10
	// cap(i) // 假设的错误用法，类型检查器会报错，因为 cap 的参数不是 slice、array 或 channel

	p := new(int) // 类型检查器会检查 new 的参数是否是类型
	println(p)

	// unsafe 包的例子 (需要 import "unsafe")
	var x int = 10
	ptr := &x
	// addr := unsafe.Pointer(ptr) // 将 *int 转换为 unsafe.Pointer
	// newPtr := unsafe.Add(addr, 8) // 假设地址偏移 8 字节 (需要 Go 1.17+)
}
```

**假设的输入与输出 (针对 `len` 函数):**

**假设输入 (AST 节点):**

```go
&ast.CallExpr{
    Fun: &ast.Ident{Name: "len"},
    Args: []ast.Expr{
        &ast.Ident{Name: "mySlice"}, // 假设 mySlice 是一个 []int 类型的变量
    },
}
```

**假设 `mySlice` 的类型信息:**

```go
&types.Slice{Elem: types.Typ[types.Int]}
```

**输出 (部分 `operand` 信息):**

```go
&types.Operand{
    Mode: types.Value, // 或者 types.Constant_ 如果 mySlice 是一个可以在编译时确定长度的数组
    Type: types.Typ[types.Int],
    // ...其他字段
}
```

**假设的输入与输出 (针对 `append` 函数):**

**假设输入 (AST 节点):**

```go
&ast.CallExpr{
    Fun: &ast.Ident{Name: "append"},
    Args: []ast.Expr{
        &ast.Ident{Name: "mySlice"}, // 假设 mySlice 是一个 []int 类型的变量
        &ast.BasicLit{Kind: token.INT, Value: "5"},
    },
    Ellipsis: token.NoPos,
}
```

**假设 `mySlice` 的类型信息:**

```go
&types.Slice{Elem: types.Typ[types.Int]}
```

**输出 (部分 `operand` 信息):**

```go
&types.Operand{
    Mode: types.Value,
    Type: &types.Slice{Elem: types.Typ[types.Int]}, // append 返回的仍然是切片类型
    // ...其他字段
}
```

**代码推理:**

代码通过 `switch id` 语句，针对不同的内置函数执行不同的类型检查逻辑。例如，对于 `len` 和 `cap`，它会检查参数的类型是否为数组、切片、字符串、channel 或 map。对于 `append`，它会检查第一个参数是否为切片，并且后续的参数是否可以赋值给切片的元素类型。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它是在 Go 编译器的类型检查阶段被调用的，而 Go 编译器的命令行参数（例如 `-o`, `-gcflags` 等）是由编译器的其他部分处理的。

**使用者易犯错的点:**

1. **`append` 的第一个参数必须是切片:**  新手容易忘记 `append` 的第一个参数必须是切片，尝试将元素追加到数组或其他类型会导致编译错误。

   ```go
   package main

   func main() {
       arr := [3]int{1, 2, 3}
       // append(arr, 4) // 错误: first argument to append must be a slice; have [3]int
       slice := arr[:]
       slice = append(slice, 4) // 正确
       println(slice...)
   }
   ```

2. **`len` 和 `cap` 的参数类型限制:**  `len` 和 `cap` 只能用于特定的类型，例如切片、数组、字符串、channel 和 map。

   ```go
   package main

   func main() {
       var i int = 10
       // len(i) // 错误: invalid argument i (variable of type int) for len
       // cap(i) // 错误: invalid argument i (variable of type int) for cap

       s := []int{1, 2, 3}
       println(len(s)) // 正确
       println(cap(s)) // 正确
   }
   ```

3. **`make` 的参数数量和类型:** `make` 用于创建切片、map 或 channel，其参数数量和类型取决于要创建的类型。

   ```go
   package main

   func main() {
       // make(10) // 错误: not enough arguments in call to make
       // make([]int) // 错误: missing len argument to make([]int)
       s := make([]int, 10)        // 正确: 创建长度为 10 的切片
       m := make(map[string]int) // 正确: 创建 map
       ch := make(chan int)       // 正确: 创建 channel
       println(len(s), len(m))
       close(ch)
   }
   ```

4. **`delete` 用于 map:** `delete` 只能用于删除 map 中的元素。

   ```go
   package main

   func main() {
       s := []int{1, 2, 3}
       m := map[string]int{"a": 1, "b": 2}
       // delete(s, 0) // 错误: first argument to delete must be a map; have []int
       delete(m, "a") // 正确
       println(len(m))
   }
   ```

理解这些易犯的错误点有助于更好地使用 Go 语言的内置函数，避免编译错误。这段代码在编译器的早期阶段就捕获了这些类型错误，提高了代码的可靠性。

### 提示词
```
这是路径为go/src/go/types/builtins.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Code generated by "go test -run=Generate -write=all"; DO NOT EDIT.
// Source: ../../cmd/compile/internal/types2/builtins.go

// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements typechecking of builtin function calls.

package types

import (
	"go/ast"
	"go/constant"
	"go/token"
	. "internal/types/errors"
)

// builtin type-checks a call to the built-in specified by id and
// reports whether the call is valid, with *x holding the result;
// but x.expr is not set. If the call is invalid, the result is
// false, and *x is undefined.
func (check *Checker) builtin(x *operand, call *ast.CallExpr, id builtinId) (_ bool) {
	argList := call.Args

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
				p = make(map[*ast.CallExpr]bool)
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
		selx, _ := ast.Unparen(arg0).(*ast.SelectorExpr)
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
		sel := selx.Sel.Name
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
			check.dump("%v: trace() without arguments", call.Pos())
			x.mode = novalue
			break
		}
		var t operand
		x1 := x
		for _, arg := range argList {
			check.rawExpr(nil, x1, arg, nil, false) // permit trace for types, e.g.: new(trace(T))
			check.dump("%v: %s", x1.Pos(), x1)
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