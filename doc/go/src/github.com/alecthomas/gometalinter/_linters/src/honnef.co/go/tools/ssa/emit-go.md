Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understanding the Goal:** The request asks for the functionality of the provided Go code, its use cases with examples, handling of command-line arguments (if any), and potential pitfalls for users. The path `go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/ssa/emit.go` strongly suggests this code is related to generating Static Single Assignment (SSA) form for Go programs.

2. **Initial Code Scan - Identifying Key Functions:**  A quick skim reveals a set of functions with names like `emitNew`, `emitLoad`, `emitArith`, `emitCompare`, `emitConv`, `emitStore`, `emitJump`, `emitIf`, etc. The prefix "emit" strongly hints at their purpose: generating SSA instructions.

3. **Analyzing Individual Functions:** Now, let's examine each function more closely:

    * **`emitNew(f *Function, typ types.Type, pos token.Pos) *Alloc`**:  The name and parameters suggest allocating memory on the heap. The return type `*Alloc` confirms this, as `Alloc` is likely an SSA instruction representing allocation.

    * **`emitLoad(f *Function, addr Value) *UnOp`**: "Load" and taking an `addr` suggest reading a value from memory. `*UnOp` with `Op: token.MUL` (dereference operator in Go) confirms it's a load operation.

    * **`emitDebugRef(f *Function, e ast.Expr, v Value, isAddr bool)`**: "DebugRef" indicates this is related to debugging information. It associates an expression (`ast.Expr`) with an SSA value (`Value`).

    * **`emitArith(f *Function, op token.Token, x, y Value, t types.Type, pos token.Pos) Value`**: "Arith" clearly points to arithmetic operations. It takes an operator (`token.Token`) and two operands (`x`, `y`). The type `t` is likely the result type.

    * **`emitCompare(f *Function, op token.Token, x, y Value, pos token.Pos) Value`**: Similar to `emitArith`, but for comparison operations. It returns a boolean value.

    * **`isValuePreserving(ut_src, ut_dst types.Type) bool`**: This function checks if a type conversion is just a type change without altering the underlying value representation. This is an internal helper function for `emitConv`.

    * **`emitConv(f *Function, val Value, typ types.Type) Value`**: "Conv" clearly stands for conversion. This function handles implicit and explicit type conversions.

    * **`emitStore(f *Function, addr, val Value, pos token.Pos) *Store`**: "Store" and taking an `addr` and `val` signify writing a value to memory. `*Store` is the corresponding SSA instruction.

    * **`emitJump(f *Function, target *BasicBlock)`**: "Jump" indicates an unconditional jump in the control flow.

    * **`emitIf(f *Function, cond Value, tblock, fblock *BasicBlock)`**: "If" indicates a conditional jump based on a condition.

    * **`emitExtract(f *Function, tuple Value, index int) Value`**: "Extract" suggests accessing an element from a tuple (likely representing multiple return values).

    * **`emitTypeAssert(f *Function, x Value, t types.Type, pos token.Pos) Value`**: This deals with type assertions in Go (`x.(T)`).

    * **`emitTypeTest(f *Function, x Value, t types.Type, pos token.Pos) Value`**: Handles type assertions with the "comma ok" idiom (`value, ok := x.(T)`).

    * **`emitTailCall(f *Function, call *Call)`**: Specifically for tail calls, an optimization technique.

    * **`emitImplicitSelections(f *Function, v Value, indices []int) Value`**:  Handles accessing nested fields within structs.

    * **`emitFieldSelection(f *Function, v Value, index int, wantAddr bool, id *ast.Ident) Value`**:  Selects a specific field of a struct.

    * **`zeroValue(f *Function, t types.Type) Value`**: Creates a zero value for a given type.

    * **`createRecoverBlock(f *Function)`**:  Handles the creation of a basic block for `recover()` in `panic/recover` scenarios.

4. **Inferring the Overall Functionality:**  By examining these individual functions, a clear picture emerges: this code is responsible for translating Go language constructs into their corresponding SSA representation. It handles memory allocation, loads, stores, arithmetic and comparison operations, type conversions, control flow (jumps, if statements), tuple manipulation, type assertions, and more.

5. **Providing Go Code Examples:** Now, for each function, think of simple Go code snippets that would require the corresponding SSA instruction to be generated. This involves mapping high-level Go constructs to low-level SSA operations.

6. **Considering Command-Line Arguments:**  Review the code. There's no explicit parsing of command-line arguments within this snippet. However, the context (`gometalinter`, `ssa`) suggests it's part of a larger tool. The SSA generation might be triggered by a compiler or static analysis tool, which *could* have command-line arguments. It's important to state that *this specific snippet* doesn't handle them.

7. **Identifying Common Pitfalls:**  Think about how a *user* (in this case, likely a compiler developer or someone working on SSA analysis) might misuse these functions. The key here is to focus on potential errors related to type mismatches or incorrect usage of the `emit` functions.

8. **Structuring the Answer:** Finally, organize the findings in a clear and logical manner, using the headings requested in the prompt: "功能", "Go语言功能实现举例", "代码推理", "命令行参数", and "使用者易犯错的点". Use clear and concise language. Provide concrete examples for better understanding.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this code directly interacts with the Go compiler. **Correction:**  It's more likely a part of a static analysis tool or an intermediate step in compilation, generating SSA *after* parsing and type checking.

* **Initial thought:**  Focus heavily on low-level details of SSA. **Correction:** While understanding SSA is crucial, the request focuses on the *Go language features* being represented in SSA. The explanation should bridge the gap between Go syntax and the SSA operations.

* **Initial thought:**  Try to cover every single edge case. **Correction:** Focus on the most common and illustrative examples. The goal is understanding, not exhaustive documentation.

By following this systematic process of code analysis, example generation, and consideration of the context, we can arrive at a comprehensive and accurate answer to the given request.
这段代码是 Go 语言中 `ssa` 包的一部分，位于 `emit.go` 文件中。 `ssa` 包的作用是将 Go 语言的抽象语法树（AST）转换为静态单赋值形式（SSA）的中间表示。`emit.go` 文件中的代码主要负责生成各种 SSA 指令。

以下是它包含的功能的详细列表：

**核心功能：生成 SSA 指令**

* **`emitNew(f *Function, typ types.Type, pos token.Pos) *Alloc`**:
    * 功能：在函数 `f` 中生成一个新的 `Alloc` 指令，用于在堆上分配类型为 `typ` 的对象。
    * 对应 Go 语言功能：使用 `new()` 函数或取结构体字面量的地址（`&Struct{}`) 在堆上分配内存。
    * Go 代码示例：
      ```go
      package main

      type MyStruct struct {
          Value int
      }

      func main() {
          s := new(MyStruct) // 或者 s := &MyStruct{Value: 10}
          println(s.Value)
      }
      ```
      * 假设输入：函数 `main` 的 SSA 表示，类型 `MyStruct`。
      * 输出：一个 `Alloc` 指令，其类型为 `*MyStruct`。

* **`emitLoad(f *Function, addr Value) *UnOp`**:
    * 功能：在函数 `f` 中生成一个 `UnOp` 指令，用于加载地址 `addr` 处的值到一个新的临时变量中。
    * 对应 Go 语言功能：解引用指针操作 `*ptr`。
    * Go 代码示例：
      ```go
      package main

      func main() {
          x := 10
          ptr := &x
          y := *ptr
          println(y)
      }
      ```
      * 假设输入：一个表示 `ptr` 的 SSA 值（其类型为 `*int`）。
      * 输出：一个 `UnOp` 指令，其操作符为 `token.MUL` (代表解引用)，类型为 `int`。

* **`emitDebugRef(f *Function, e ast.Expr, v Value, isAddr bool)`**:
    * 功能：在函数 `f` 中生成一个 `DebugRef` 伪指令，用于将表达式 `e` 与 SSA 值 `v` 关联起来。这主要用于调试目的。
    * 对应 Go 语言功能：任何产生值的表达式，例如变量名、字面量等。
    * Go 代码示例：
      ```go
      package main

      func main() {
          x := 10 // 这里的 x 就是一个 ast.Expr，10 是一个 Value
          println(x)
      }
      ```
      * 假设输入：表达式 `x` 的 AST 节点，表示 `x` 的 SSA 值，`isAddr` 为 `false`。
      * 输出：一个 `DebugRef` 指令，将 `x` 的 AST 节点与其 SSA 值关联。

* **`emitArith(f *Function, op token.Token, x, y Value, t types.Type, pos token.Pos) Value`**:
    * 功能：在函数 `f` 中生成一个 `BinOp` 指令，用于计算二元算术或位运算 `op(x, y)`。
    * 对应 Go 语言功能：加法、减法、乘法、除法、取余、位运算等。
    * Go 代码示例：
      ```go
      package main

      func main() {
          a := 5
          b := 3
          c := a + b
          println(c)
      }
      ```
      * 假设输入：操作符 `token.ADD`，表示 `a` 和 `b` 的 SSA 值，结果类型 `int`。
      * 输出：一个 `BinOp` 指令，操作符为 `token.ADD`，操作数为表示 `a` 和 `b` 的 SSA 值，类型为 `int`。

* **`emitCompare(f *Function, op token.Token, x, y Value, pos token.Pos) Value`**:
    * 功能：在函数 `f` 中生成一个 `BinOp` 指令，用于计算布尔比较 `x op y`。
    * 对应 Go 语言功能：等于、不等于、大于、小于、大于等于、小于等于比较。
    * Go 代码示例：
      ```go
      package main

      func main() {
          a := 5
          b := 3
          result := a > b
          println(result)
      }
      ```
      * 假设输入：操作符 `token.GTR`，表示 `a` 和 `b` 的 SSA 值。
      * 输出：一个 `BinOp` 指令，操作符为 `token.GTR`，操作数为表示 `a` 和 `b` 的 SSA 值，类型为 `bool`。

* **`emitConv(f *Function, val Value, typ types.Type) Value`**:
    * 功能：在函数 `f` 中生成一个类型转换指令，将 SSA 值 `val` 转换为类型 `typ`。
    * 对应 Go 语言功能：显式或隐式类型转换。
    * Go 代码示例：
      ```go
      package main

      func main() {
          var i int = 10
          var f float64 = float64(i) // 显式转换
          println(f)

          var a int32 = 10
          var b int64 = a // 隐式转换（在赋值场景下）
          println(b)
      }
      ```
      * 假设输入：表示整数 `i` 的 SSA 值，目标类型 `float64`。
      * 输出：一个 `Convert` 或 `ChangeType` 或 `MakeInterface` 指令，取决于具体的类型转换场景，其结果类型为 `float64`。

* **`emitStore(f *Function, addr, val Value, pos token.Pos) *Store`**:
    * 功能：在函数 `f` 中生成一个 `Store` 指令，用于将 SSA 值 `val` 存储到地址 `addr` 处。
    * 对应 Go 语言功能：赋值操作。
    * Go 代码示例：
      ```go
      package main

      func main() {
          x := 0
          x = 10
          println(x)
      }
      ```
      * 假设输入：表示变量 `x` 地址的 SSA 值，表示值 `10` 的 SSA 值。
      * 输出：一个 `Store` 指令，将表示值 `10` 的 SSA 值存储到表示 `x` 地址的 SSA 值所指向的内存位置。

* **`emitJump(f *Function, target *BasicBlock)`**:
    * 功能：在函数 `f` 中生成一个无条件跳转到 `target` 基本块的指令。
    * 对应 Go 语言功能：`goto` 语句 (虽然不常用，但 SSA 需要表示)。
    * Go 代码示例：
      ```go
      package main

      func main() {
          println("开始")
          goto END
          println("这行不会被执行")
      END:
          println("结束")
      }
      ```
      * 假设输入：目标基本块 `END`。
      * 输出：一个 `Jump` 指令，跳转到 `END` 基本块。

* **`emitIf(f *Function, cond Value, tblock, fblock *BasicBlock)`**:
    * 功能：在函数 `f` 中生成一个条件跳转指令，如果条件 `cond` 为真，则跳转到 `tblock`，否则跳转到 `fblock`。
    * 对应 Go 语言功能：`if` 语句。
    * Go 代码示例：
      ```go
      package main

      func main() {
          x := 5
          if x > 3 {
              println("x 大于 3")
          } else {
              println("x 小于等于 3")
          }
      }
      ```
      * 假设输入：表示条件 `x > 3` 的 SSA 值，真分支基本块，假分支基本块。
      * 输出：一个 `If` 指令，条件为表示 `x > 3` 的 SSA 值，跳转目标为真分支和假分支基本块。

* **`emitExtract(f *Function, tuple Value, index int) Value`**:
    * 功能：在函数 `f` 中生成一个 `Extract` 指令，用于从元组 `tuple` 中提取索引为 `index` 的元素。
    * 对应 Go 语言功能：访问多返回值函数的某个返回值。
    * Go 代码示例：
      ```go
      package main

      func multiReturn() (int, string) {
          return 10, "hello"
      }

      func main() {
          val, str := multiReturn()
          println(val)
          println(str)
      }
      ```
      * 假设输入：表示 `multiReturn()` 调用结果的元组 SSA 值，索引 `0` 或 `1`。
      * 输出：一个 `Extract` 指令，提取元组中指定索引的元素，其类型为对应的返回值类型。

* **`emitTypeAssert(f *Function, x Value, t types.Type, pos token.Pos) Value`**:
    * 功能：在函数 `f` 中生成一个 `TypeAssert` 指令，用于执行类型断言 `x.(t)`。
    * 对应 Go 语言功能：类型断言。
    * Go 代码示例：
      ```go
      package main

      import "fmt"

      func main() {
          var i interface{} = 10
          value := i.(int)
          fmt.Println(value)
      }
      ```
      * 假设输入：表示接口变量 `i` 的 SSA 值，断言的类型 `int`。
      * 输出：一个 `TypeAssert` 指令，断言 `i` 的类型为 `int`，其结果类型为 `int`。

* **`emitTypeTest(f *Function, x Value, t types.Type, pos token.Pos) Value`**:
    * 功能：在函数 `f` 中生成一个 `TypeAssert` 指令，用于执行带逗号 ok 的类型断言 `value, ok := x.(t)`。
    * 对应 Go 语言功能：带逗号 ok 的类型断言。
    * Go 代码示例：
      ```go
      package main

      import "fmt"

      func main() {
          var i interface{} = 10
          value, ok := i.(int)
          fmt.Println(value, ok)
      }
      ```
      * 假设输入：表示接口变量 `i` 的 SSA 值，断言的类型 `int`。
      * 输出：一个 `TypeAssert` 指令，断言 `i` 的类型为 `int`，其结果类型为一个包含值和布尔值的元组。

* **`emitTailCall(f *Function, call *Call)`**:
    * 功能：在函数 `f` 中生成一个尾调用指令。
    * 对应 Go 语言功能：在满足尾调用优化条件的情况下，函数调用的优化形式。
    * Go 代码示例：
      ```go
      package main

      func factorial(n int, acc int) int {
          if n == 0 {
              return acc
          }
          return factorial(n-1, n*acc) // 尾调用
      }

      func main() {
          println(factorial(5, 1))
      }
      ```
      * 假设输入：表示 `factorial(n-1, n*acc)` 调用的 `Call` 对象。
      * 输出：一个 `Call` 指令，标记为尾调用。

* **`emitImplicitSelections(f *Function, v Value, indices []int) Value`**:
    * 功能：在函数 `f` 中生成指令，用于应用一系列隐式字段选择到值 `v`。这通常用于访问嵌套的匿名结构体字段。
    * 对应 Go 语言功能：访问匿名结构体的内嵌字段。
    * Go 代码示例：
      ```go
      package main

      type Inner struct {
          Value int
      }

      type Outer struct {
          Inner
      }

      func main() {
          o := Outer{Inner{Value: 10}}
          println(o.Value) // 隐式访问 Inner 的 Value 字段
      }
      ```
      * 假设输入：表示 `o` 的 SSA 值，索引 `[]int{0}` (代表 `Inner` 字段)。
      * 输出：一个 `Field` 或 `FieldAddr` 指令，访问 `o` 的 `Inner` 字段，然后根据需要可能再次生成 `Field` 或 `Load` 指令访问 `Value` 字段。

* **`emitFieldSelection(f *Function, v Value, index int, wantAddr bool, id *ast.Ident) Value`**:
    * 功能：在函数 `f` 中生成指令，用于选择值 `v` 的第 `index` 个字段。`wantAddr` 指示是否需要字段的地址。
    * 对应 Go 语言功能：访问结构体字段。
    * Go 代码示例：
      ```go
      package main

      type MyStruct struct {
          Value int
          Name  string
      }

      func main() {
          s := MyStruct{Value: 10, Name: "test"}
          println(s.Value)
          ptr := &s.Name
          println(*ptr)
      }
      ```
      * 假设输入：表示 `s` 的 SSA 值，索引 `0` (代表 `Value` 字段)，`wantAddr` 为 `false`。
      * 输出：一个 `Field` 指令，访问 `s` 的 `Value` 字段。
      * 假设输入：表示 `s` 的 SSA 值，索引 `1` (代表 `Name` 字段)，`wantAddr` 为 `true`。
      * 输出：一个 `FieldAddr` 指令，获取 `s` 的 `Name` 字段的地址。

* **`zeroValue(f *Function, t types.Type) Value`**:
    * 功能：在函数 `f` 中生成代码，产生类型 `t` 的零值。
    * 对应 Go 语言功能：变量的默认零值。
    * Go 代码示例：
      ```go
      package main

      func main() {
          var i int     // 默认值为 0
          var s string  // 默认值为 ""
          var b bool    // 默认值为 false
          println(i, s, b)
      }
      ```
      * 假设输入：类型 `int`。
      * 输出：一个表示常量 `0` 的 SSA 值。
      * 假设输入：类型 `string`。
      * 输出：一个表示空字符串的 SSA 值。
      * 假设输入：类型为结构体或数组。
      * 输出：一个 `Load` 指令，加载一个新分配的局部变量（其默认值为零）。

* **`createRecoverBlock(f *Function)`**:
    * 功能：在函数 `f` 中创建一个用于处理 `recover()` 调用的代码块，并设置 `f.Recover`。
    * 对应 Go 语言功能：`panic` 和 `recover` 机制中的 `recover()` 函数。
    * Go 代码示例：
      ```go
      package main

      import "fmt"

      func main() {
          defer func() {
              if r := recover(); r != nil {
                  fmt.Println("Recovered from:", r)
              }
          }()
          panic("something went wrong")
      }
      ```
      * 输出：创建一个基本块，包含返回值的加载（如果结果参数已命名）或零值的生成，以及一个 `Return` 指令。

**涉及的代码推理和假设的输入与输出：**

上面的每个功能介绍中都包含了代码推理和假设的输入输出。核心思想是将 Go 语言的语法结构映射到相应的 SSA 指令。例如，看到 `a + b`，就推理出需要生成一个 `BinOp` 指令，其操作符是加法，操作数是 `a` 和 `b` 对应的 SSA 值。

**命令行参数：**

这段代码本身并不直接处理命令行参数。它是 `ssa` 包的一部分，而 `ssa` 包通常被更高级别的工具（如 Go 编译器或静态分析工具）使用。这些工具可能会有自己的命令行参数，用于控制 SSA 生成的某些方面，例如是否启用调试信息。

**使用者易犯错的点：**

对于 `ssa` 包的使用者（通常是编译器或静态分析工具的开发者），一些易犯错的点可能包括：

* **类型转换不当：** 在使用 `emitConv` 时，需要确保转换是合法的，并且理解不同类型转换操作（如 `ChangeType`，`Convert`，`MakeInterface`）之间的区别。错误的类型转换可能导致生成的 SSA 代码不正确。
    * **例子：** 尝试将一个不兼容的类型转换为另一个类型，例如将字符串直接转换为整数而不进行解析。
* **地址和值的混淆：** 在使用 `emitLoad` 和 `emitStore` 时，需要清楚地知道处理的是地址还是值。错误地将值当作地址或反之会导致运行时错误或生成错误的 SSA。
    * **例子：**  尝试 `emitLoad` 一个不是指针类型的值。
* **控制流图的构建错误：** 在使用 `emitJump` 和 `emitIf` 时，需要正确地连接基本块，确保控制流的正确性。错误的控制流可能导致程序执行逻辑错误。
    * **例子：** 在 `if` 语句后忘记连接到 `else` 分支。
* **对于多返回值函数的处理：** 在使用 `emitExtract` 时，需要确保提取的索引是有效的。
    * **例子：** 尝试提取超出多返回值函数返回数量的索引。

总而言之，`emit.go` 中的代码是 Go 语言 SSA 生成的关键部分，它提供了一系列函数，用于将 Go 语言的各种语法结构转换为底层的 SSA 指令，为后续的优化和分析奠定基础。理解这些函数的功能对于理解 Go 编译器的内部工作原理以及进行静态分析工具的开发至关重要。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/ssa/emit.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

// Helpers for emitting SSA instructions.

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
)

// emitNew emits to f a new (heap Alloc) instruction allocating an
// object of type typ.  pos is the optional source location.
//
func emitNew(f *Function, typ types.Type, pos token.Pos) *Alloc {
	v := &Alloc{Heap: true}
	v.setType(types.NewPointer(typ))
	v.setPos(pos)
	f.emit(v)
	return v
}

// emitLoad emits to f an instruction to load the address addr into a
// new temporary, and returns the value so defined.
//
func emitLoad(f *Function, addr Value) *UnOp {
	v := &UnOp{Op: token.MUL, X: addr}
	v.setType(deref(addr.Type()))
	f.emit(v)
	return v
}

// emitDebugRef emits to f a DebugRef pseudo-instruction associating
// expression e with value v.
//
func emitDebugRef(f *Function, e ast.Expr, v Value, isAddr bool) {
	if !f.debugInfo() {
		return // debugging not enabled
	}
	if v == nil || e == nil {
		panic("nil")
	}
	var obj types.Object
	e = unparen(e)
	if id, ok := e.(*ast.Ident); ok {
		if isBlankIdent(id) {
			return
		}
		obj = f.Pkg.objectOf(id)
		switch obj.(type) {
		case *types.Nil, *types.Const, *types.Builtin:
			return
		}
	}
	f.emit(&DebugRef{
		X:      v,
		Expr:   e,
		IsAddr: isAddr,
		object: obj,
	})
}

// emitArith emits to f code to compute the binary operation op(x, y)
// where op is an eager shift, logical or arithmetic operation.
// (Use emitCompare() for comparisons and Builder.logicalBinop() for
// non-eager operations.)
//
func emitArith(f *Function, op token.Token, x, y Value, t types.Type, pos token.Pos) Value {
	switch op {
	case token.SHL, token.SHR:
		x = emitConv(f, x, t)
		// y may be signed or an 'untyped' constant.
		// TODO(adonovan): whence signed values?
		if b, ok := y.Type().Underlying().(*types.Basic); ok && b.Info()&types.IsUnsigned == 0 {
			y = emitConv(f, y, types.Typ[types.Uint64])
		}

	case token.ADD, token.SUB, token.MUL, token.QUO, token.REM, token.AND, token.OR, token.XOR, token.AND_NOT:
		x = emitConv(f, x, t)
		y = emitConv(f, y, t)

	default:
		panic("illegal op in emitArith: " + op.String())

	}
	v := &BinOp{
		Op: op,
		X:  x,
		Y:  y,
	}
	v.setPos(pos)
	v.setType(t)
	return f.emit(v)
}

// emitCompare emits to f code compute the boolean result of
// comparison comparison 'x op y'.
//
func emitCompare(f *Function, op token.Token, x, y Value, pos token.Pos) Value {
	xt := x.Type().Underlying()
	yt := y.Type().Underlying()

	// Special case to optimise a tagless SwitchStmt so that
	// these are equivalent
	//   switch { case e: ...}
	//   switch true { case e: ... }
	//   if e==true { ... }
	// even in the case when e's type is an interface.
	// TODO(adonovan): opt: generalise to x==true, false!=y, etc.
	if x == vTrue && op == token.EQL {
		if yt, ok := yt.(*types.Basic); ok && yt.Info()&types.IsBoolean != 0 {
			return y
		}
	}

	if types.Identical(xt, yt) {
		// no conversion necessary
	} else if _, ok := xt.(*types.Interface); ok {
		y = emitConv(f, y, x.Type())
	} else if _, ok := yt.(*types.Interface); ok {
		x = emitConv(f, x, y.Type())
	} else if _, ok := x.(*Const); ok {
		x = emitConv(f, x, y.Type())
	} else if _, ok := y.(*Const); ok {
		y = emitConv(f, y, x.Type())
	} else {
		// other cases, e.g. channels.  No-op.
	}

	v := &BinOp{
		Op: op,
		X:  x,
		Y:  y,
	}
	v.setPos(pos)
	v.setType(tBool)
	return f.emit(v)
}

// isValuePreserving returns true if a conversion from ut_src to
// ut_dst is value-preserving, i.e. just a change of type.
// Precondition: neither argument is a named type.
//
func isValuePreserving(ut_src, ut_dst types.Type) bool {
	// Identical underlying types?
	if structTypesIdentical(ut_dst, ut_src) {
		return true
	}

	switch ut_dst.(type) {
	case *types.Chan:
		// Conversion between channel types?
		_, ok := ut_src.(*types.Chan)
		return ok

	case *types.Pointer:
		// Conversion between pointers with identical base types?
		_, ok := ut_src.(*types.Pointer)
		return ok
	}
	return false
}

// emitConv emits to f code to convert Value val to exactly type typ,
// and returns the converted value.  Implicit conversions are required
// by language assignability rules in assignments, parameter passing,
// etc.  Conversions cannot fail dynamically.
//
func emitConv(f *Function, val Value, typ types.Type) Value {
	t_src := val.Type()

	// Identical types?  Conversion is a no-op.
	if types.Identical(t_src, typ) {
		return val
	}

	ut_dst := typ.Underlying()
	ut_src := t_src.Underlying()

	// Just a change of type, but not value or representation?
	if isValuePreserving(ut_src, ut_dst) {
		c := &ChangeType{X: val}
		c.setType(typ)
		return f.emit(c)
	}

	// Conversion to, or construction of a value of, an interface type?
	if _, ok := ut_dst.(*types.Interface); ok {
		// Assignment from one interface type to another?
		if _, ok := ut_src.(*types.Interface); ok {
			c := &ChangeInterface{X: val}
			c.setType(typ)
			return f.emit(c)
		}

		// Untyped nil constant?  Return interface-typed nil constant.
		if ut_src == tUntypedNil {
			return nilConst(typ)
		}

		// Convert (non-nil) "untyped" literals to their default type.
		if t, ok := ut_src.(*types.Basic); ok && t.Info()&types.IsUntyped != 0 {
			val = emitConv(f, val, DefaultType(ut_src))
		}

		f.Pkg.Prog.needMethodsOf(val.Type())
		mi := &MakeInterface{X: val}
		mi.setType(typ)
		return f.emit(mi)
	}

	// Conversion of a compile-time constant value?
	if c, ok := val.(*Const); ok {
		if _, ok := ut_dst.(*types.Basic); ok || c.IsNil() {
			// Conversion of a compile-time constant to
			// another constant type results in a new
			// constant of the destination type and
			// (initially) the same abstract value.
			// We don't truncate the value yet.
			return NewConst(c.Value, typ)
		}

		// We're converting from constant to non-constant type,
		// e.g. string -> []byte/[]rune.
	}

	// A representation-changing conversion?
	// At least one of {ut_src,ut_dst} must be *Basic.
	// (The other may be []byte or []rune.)
	_, ok1 := ut_src.(*types.Basic)
	_, ok2 := ut_dst.(*types.Basic)
	if ok1 || ok2 {
		c := &Convert{X: val}
		c.setType(typ)
		return f.emit(c)
	}

	panic(fmt.Sprintf("in %s: cannot convert %s (%s) to %s", f, val, val.Type(), typ))
}

// emitStore emits to f an instruction to store value val at location
// addr, applying implicit conversions as required by assignability rules.
//
func emitStore(f *Function, addr, val Value, pos token.Pos) *Store {
	s := &Store{
		Addr: addr,
		Val:  emitConv(f, val, deref(addr.Type())),
		pos:  pos,
	}
	f.emit(s)
	return s
}

// emitJump emits to f a jump to target, and updates the control-flow graph.
// Postcondition: f.currentBlock is nil.
//
func emitJump(f *Function, target *BasicBlock) {
	b := f.currentBlock
	b.emit(new(Jump))
	addEdge(b, target)
	f.currentBlock = nil
}

// emitIf emits to f a conditional jump to tblock or fblock based on
// cond, and updates the control-flow graph.
// Postcondition: f.currentBlock is nil.
//
func emitIf(f *Function, cond Value, tblock, fblock *BasicBlock) {
	b := f.currentBlock
	b.emit(&If{Cond: cond})
	addEdge(b, tblock)
	addEdge(b, fblock)
	f.currentBlock = nil
}

// emitExtract emits to f an instruction to extract the index'th
// component of tuple.  It returns the extracted value.
//
func emitExtract(f *Function, tuple Value, index int) Value {
	e := &Extract{Tuple: tuple, Index: index}
	e.setType(tuple.Type().(*types.Tuple).At(index).Type())
	return f.emit(e)
}

// emitTypeAssert emits to f a type assertion value := x.(t) and
// returns the value.  x.Type() must be an interface.
//
func emitTypeAssert(f *Function, x Value, t types.Type, pos token.Pos) Value {
	a := &TypeAssert{X: x, AssertedType: t}
	a.setPos(pos)
	a.setType(t)
	return f.emit(a)
}

// emitTypeTest emits to f a type test value,ok := x.(t) and returns
// a (value, ok) tuple.  x.Type() must be an interface.
//
func emitTypeTest(f *Function, x Value, t types.Type, pos token.Pos) Value {
	a := &TypeAssert{
		X:            x,
		AssertedType: t,
		CommaOk:      true,
	}
	a.setPos(pos)
	a.setType(types.NewTuple(
		newVar("value", t),
		varOk,
	))
	return f.emit(a)
}

// emitTailCall emits to f a function call in tail position.  The
// caller is responsible for all fields of 'call' except its type.
// Intended for wrapper methods.
// Precondition: f does/will not use deferred procedure calls.
// Postcondition: f.currentBlock is nil.
//
func emitTailCall(f *Function, call *Call) {
	tresults := f.Signature.Results()
	nr := tresults.Len()
	if nr == 1 {
		call.typ = tresults.At(0).Type()
	} else {
		call.typ = tresults
	}
	tuple := f.emit(call)
	var ret Return
	switch nr {
	case 0:
		// no-op
	case 1:
		ret.Results = []Value{tuple}
	default:
		for i := 0; i < nr; i++ {
			v := emitExtract(f, tuple, i)
			// TODO(adonovan): in principle, this is required:
			//   v = emitConv(f, o.Type, f.Signature.Results[i].Type)
			// but in practice emitTailCall is only used when
			// the types exactly match.
			ret.Results = append(ret.Results, v)
		}
	}
	f.emit(&ret)
	f.currentBlock = nil
}

// emitImplicitSelections emits to f code to apply the sequence of
// implicit field selections specified by indices to base value v, and
// returns the selected value.
//
// If v is the address of a struct, the result will be the address of
// a field; if it is the value of a struct, the result will be the
// value of a field.
//
func emitImplicitSelections(f *Function, v Value, indices []int) Value {
	for _, index := range indices {
		fld := deref(v.Type()).Underlying().(*types.Struct).Field(index)

		if isPointer(v.Type()) {
			instr := &FieldAddr{
				X:     v,
				Field: index,
			}
			instr.setType(types.NewPointer(fld.Type()))
			v = f.emit(instr)
			// Load the field's value iff indirectly embedded.
			if isPointer(fld.Type()) {
				v = emitLoad(f, v)
			}
		} else {
			instr := &Field{
				X:     v,
				Field: index,
			}
			instr.setType(fld.Type())
			v = f.emit(instr)
		}
	}
	return v
}

// emitFieldSelection emits to f code to select the index'th field of v.
//
// If wantAddr, the input must be a pointer-to-struct and the result
// will be the field's address; otherwise the result will be the
// field's value.
// Ident id is used for position and debug info.
//
func emitFieldSelection(f *Function, v Value, index int, wantAddr bool, id *ast.Ident) Value {
	fld := deref(v.Type()).Underlying().(*types.Struct).Field(index)
	if isPointer(v.Type()) {
		instr := &FieldAddr{
			X:     v,
			Field: index,
		}
		instr.setPos(id.Pos())
		instr.setType(types.NewPointer(fld.Type()))
		v = f.emit(instr)
		// Load the field's value iff we don't want its address.
		if !wantAddr {
			v = emitLoad(f, v)
		}
	} else {
		instr := &Field{
			X:     v,
			Field: index,
		}
		instr.setPos(id.Pos())
		instr.setType(fld.Type())
		v = f.emit(instr)
	}
	emitDebugRef(f, id, v, wantAddr)
	return v
}

// zeroValue emits to f code to produce a zero value of type t,
// and returns it.
//
func zeroValue(f *Function, t types.Type) Value {
	switch t.Underlying().(type) {
	case *types.Struct, *types.Array:
		return emitLoad(f, f.addLocal(t, token.NoPos))
	default:
		return zeroConst(t)
	}
}

// createRecoverBlock emits to f a block of code to return after a
// recovered panic, and sets f.Recover to it.
//
// If f's result parameters are named, the code loads and returns
// their current values, otherwise it returns the zero values of their
// type.
//
// Idempotent.
//
func createRecoverBlock(f *Function) {
	if f.Recover != nil {
		return // already created
	}
	saved := f.currentBlock

	f.Recover = f.newBasicBlock("recover")
	f.currentBlock = f.Recover

	var results []Value
	if f.namedResults != nil {
		// Reload NRPs to form value tuple.
		for _, r := range f.namedResults {
			results = append(results, emitLoad(f, r))
		}
	} else {
		R := f.Signature.Results()
		for i, n := 0, R.Len(); i < n; i++ {
			T := R.At(i).Type()

			// Return zero value of each result type.
			results = append(results, zeroValue(f, T))
		}
	}
	f.emit(&Return{Results: results})

	f.currentBlock = saved
}

"""



```