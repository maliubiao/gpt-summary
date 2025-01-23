Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a functional breakdown of the provided Go code snippet, which is a part of the Go compiler's type checking phase. The key is to identify what each function does in the context of type checking Go expressions.

2. **Initial Scan for Function Names:** I'll quickly read through the code, noting down the names of all the functions defined within the snippet. This gives me a high-level overview of the operations being performed. The function names are quite descriptive, hinting at their purpose (e.g., `tcShift`, `tcArith`, `tcCompLit`).

3. **Analyze Each Function Individually:** For each function, I'll perform the following steps:

    * **Read the Doc Comments:** The comments above each function are invaluable. They often explicitly state the function's purpose and any important constraints or return values. For example, the comment for `tcArith` clearly states its purpose and the requirement to assign the result back.

    * **Examine Input and Output Parameters:**  Understanding the types of input and output parameters helps clarify the data being processed. For instance, `tcShift` takes `ir.Node` for operands and returns `ir.Node` and `*types.Type`.

    * **Trace the Logic:** I'll carefully read the code within each function, paying attention to:
        * **Key Operations:**  What are the core actions being performed (e.g., checking types, creating new nodes, calling other functions)?
        * **Error Handling:** How are type errors detected and reported (e.g., using `base.Errorf`)?
        * **Type Conversions:** Are there any explicit or implicit type conversions happening?
        * **Specific Checks:**  What specific conditions are being checked (e.g., integer types for shifts, comparable types for equality)?

    * **Relate to Go Language Features:**  Based on the function's name and its logic, I'll try to connect it to a specific Go language feature. For example, `tcShift` obviously relates to bitwise shift operations, `tcCompLit` to composite literals, and `tcConv` to type conversions.

4. **Synthesize Function Descriptions:** After analyzing each function, I'll write a concise description of its functionality, summarizing its purpose in the type-checking process.

5. **Identify Core Go Language Features:**  Based on the identified functions, I'll list the major Go language features handled by this code snippet. This provides a broader context.

6. **Construct Go Code Examples:** For each identified Go language feature, I'll create a simple, illustrative Go code example that demonstrates the feature and how the corresponding type-checking function would be involved. This involves:

    * **Choosing relevant code:** The example should clearly showcase the language feature.
    * **Adding comments:** Comments explaining what the example does and where the type checker would intervene.
    * **Hypothesizing input and output:**  For examples involving more complex type checks (like `tcArith` or `tcCompLit`), I might specify example input expressions and what the type checker would likely infer or produce.

7. **Address Command-Line Arguments and Common Mistakes (If Applicable):**  I'll review the code to see if any functions explicitly handle command-line arguments (like compiler flags). In this snippet, there isn't much explicit command-line argument handling. For common mistakes, I'll consider potential type errors that developers might make when using the features handled by this code. For example, trying to compare non-comparable types or using incorrect types in composite literals.

8. **Review and Refine:** Finally, I'll reread my entire response to ensure accuracy, clarity, and completeness. I'll check for any inconsistencies or areas where I could provide more detail or better examples. I'll also make sure the code examples are syntactically correct and easy to understand.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus on the exact data structures used by the compiler.
* **Correction:** Realized the request is about *functionality* and *Go language features*, so focusing on the high-level purpose and examples is more relevant.
* **Initial thought:** Try to provide very detailed step-by-step execution traces of the type checker.
* **Correction:**  This would be too complex and might not be what the user needs. Focus on the *what* and *why* rather than the low-level *how*.
* **Realization:** Some functions are more straightforward to explain than others. For complex functions like `tcCompLit`, breaking down the different cases (arrays, slices, maps, structs) is important.
* **Emphasis:**  The importance of the doc comments in understanding the function's purpose.

By following these steps, I can provide a comprehensive and informative answer that addresses all aspects of the user's request.
这段代码是 Go 语言编译器 `cmd/compile/internal/typecheck` 包中 `expr.go` 文件的一部分，主要负责 **类型检查 Go 语言的各种表达式**。它定义了一些函数，用于对表达式进行静态类型分析，确保它们符合 Go 语言的类型规则。

以下是其中各个函数的主要功能：

* **`tcShift(n, l, r ir.Node) (ir.Node, ir.Node, *types.Type)`:**
    * **功能:**  类型检查位移操作 (例如 `<<`, `>>`) 的操作数。
    * **推理:** 位移操作要求右操作数是整型，左操作数也通常是整型。此函数检查这些类型约束。
    * **Go 代码示例:**
        ```go
        package main

        func main() {
            var a int = 10
            var b uint = 2
            _ = a << b  // 类型检查器会调用 tcShift 来确保 b 是整型
            // _ = a << 2.5 // 编译错误，tcShift 会检测到右操作数不是整型
        }
        ```
        **假设输入:**  一个表示位移操作的 `ir.Node`，以及左右操作数的 `ir.Node`。例如，对于 `a << b`，`n` 可能代表 `<<` 操作，`l` 代表 `a`，`r` 代表 `b`。
        **输出:**  类型检查后的左右操作数 `ir.Node`，以及表达式的类型 `*types.Type`。如果类型检查失败，则返回 `nil` 类型。

* **`tcArith(n ir.Node, op ir.Op, l, r ir.Node) (ir.Node, ir.Node, *types.Type)`:**
    * **功能:** 类型检查二元算术和比较表达式的操作数 (例如 `+`, `-`, `*`, `/`, `==`, `!=`, `<`, `>`)。
    * **推理:**  算术和比较操作通常要求操作数具有兼容的类型。此函数负责进行必要的隐式类型转换或报错。对于比较操作，它还会处理接口类型的比较。
    * **Go 代码示例:**
        ```go
        package main

        func main() {
            var i int = 10
            var f float64 = 3.14
            _ = i + int(f) // tcArith 会处理 float64 到 int 的转换
            _ = i == 10.0 // tcArith 会处理 int 和 float64 的比较
            // _ = "hello" + 1 // 编译错误，tcArith 会检测到字符串和整数不能相加
        }
        ```
        **假设输入:** 一个表示算术/比较操作的 `ir.Node`，操作符 `ir.Op`，以及左右操作数的 `ir.Node`。 例如，对于 `i + f`，`n` 可能代表 `+` 操作，`l` 代表 `i`，`r` 代表 `f`。
        **输出:** 类型检查和可能转换后的左右操作数 `ir.Node`，以及表达式的类型 `*types.Type`。

* **`tcCompLit(n *ir.CompLitExpr) (res ir.Node)`:**
    * **功能:** 类型检查复合字面量 (Composite Literals)，例如 `[]int{1, 2, 3}`, `map[string]int{"a": 1}`，结构体字面量等。
    * **推理:** 复合字面量的元素类型必须与其声明的类型兼容。对于结构体字面量，它还处理字段名和值的匹配。
    * **Go 代码示例:**
        ```go
        package main

        type Point struct {
            X int
            Y int
        }

        func main() {
            _ = []int{1, 2, 3}       // tcCompLit 会检查元素类型是否为 int
            _ = map[string]int{"a": 1} // tcCompLit 会检查键值类型
            _ = Point{X: 1, Y: 2}   // tcCompLit 会检查字段名和类型
            // _ = []int{1, "hello"} // 编译错误，tcCompLit 会检测到字符串不能转换为 int
        }
        ```
        **假设输入:** 一个表示复合字面量的 `ir.CompLitExpr` 节点。例如，对于 `[]int{1, 2}`，`n` 包含类型 `[]int` 和元素列表 `1, 2`。
        **输出:** 类型检查后的 `ir.Node` (通常是输入的 `n` 本身，但可能进行了修改，例如添加了类型转换节点)。

* **`tcStructLitKey(typ *types.Type, kv *ir.KeyExpr) *ir.StructKeyExpr`:**
    * **功能:** 类型检查结构体字面量中的键 (字段名)。
    * **推理:**  结构体字面量的键必须是结构体中存在的字段名。
    * **Go 代码示例:** (与 `tcCompLit` 结合)
        ```go
        package main

        type Point struct {
            X int
            Y int
        }

        func main() {
            _ = Point{X: 1, Y: 2} // tcStructLitKey 会检查 "X" 和 "Y" 是 Point 的字段
            // _ = Point{Z: 1}    // 编译错误，tcStructLitKey 会检测到 "Z" 不是 Point 的字段
        }
        ```
        **假设输入:** 结构体的类型 `*types.Type` 和一个表示键值对的 `ir.KeyExpr` 节点。例如，对于 `X: 1`，`typ` 是 `Point` 的类型，`kv` 包含键 `X` 和值 `1`。
        **输出:** 类型检查后的 `ir.StructKeyExpr` 节点，如果键无效则返回 `nil`。

* **`tcConv(n *ir.ConvExpr) ir.Node`:**
    * **功能:** 类型检查类型转换表达式 (例如 `int(x)`, `string(b)`)。
    * **推理:**  并非所有类型之间的转换都是允许的。此函数检查转换是否合法，并可能插入必要的转换操作节点。
    * **Go 代码示例:**
        ```go
        package main

        func main() {
            var i int = 10
            var f float64 = float64(i) // tcConv 会处理 int 到 float64 的转换
            var s string = string([]byte{'h', 'i'}) // tcConv 会处理 []byte 到 string 的转换
            // _ = int("hello") // 编译错误，tcConv 会检测到字符串不能直接转换为 int
        }
        ```
        **假设输入:** 一个表示类型转换的 `ir.ConvExpr` 节点，包含要转换的表达式和目标类型。 例如，对于 `int(f)`，`n` 包含表达式 `f` 和目标类型 `int`。
        **输出:** 类型检查后的 `ir.Node` (可能是修改后的 `n`，例如更改了操作码)。

* **`DotField(pos src.XPos, x ir.Node, index int) *ir.SelectorExpr`:**
    * **功能:** 创建一个用于选择结构体或指针结构体字段的表达式节点。
    * **推理:**  根据给定的索引，从结构体类型中获取对应的字段信息。
    * **Go 代码示例:**
        ```go
        package main

        type Point struct {
            X int
            Y int
        }

        func main() {
            p := Point{1, 2}
            _ = p.X // DotField 会被用于创建选择字段 X 的表达式节点
        }
        ```
        **假设输入:**  源代码位置 `src.XPos`，结构体或指针结构体的表达式节点 `ir.Node`，以及字段的索引 `int`。
        **输出:**  一个表示字段选择的 `ir.SelectorExpr` 节点。

* **`dot(pos src.XPos, typ *types.Type, op ir.Op, x ir.Node, selection *types.Field) *ir.SelectorExpr`:**
    * **功能:**  创建一个通用的字段选择表达式节点，供 `DotField` 等函数使用。
    * **推理:**  根据提供的字段信息创建相应的选择器节点。

* **`XDotField(pos src.XPos, x ir.Node, sym *types.Sym) *ir.SelectorExpr`:**
    * **功能:**  类型检查并创建一个选择结构体字段的表达式，可以处理隐式的字段选择 (例如访问嵌入字段的字段)。
    * **推理:** 查找给定符号在给定类型的字段中，并创建相应的选择器。

* **`XDotMethod(pos src.XPos, x ir.Node, sym *types.Sym, callee bool) *ir.SelectorExpr`:**
    * **功能:** 类型检查并创建一个表示方法值的表达式 (例如 `obj.Method`)。
    * **推理:** 查找给定符号在给定类型的方法集中，并创建相应的方法值表达式。`callee` 参数指示是否是方法调用。

* **`tcDot(n *ir.SelectorExpr, top int) ir.Node`:**
    * **功能:** 类型检查字段选择表达式 (`.`)，包括结构体字段和方法。
    * **推理:** 检查左侧表达式的类型是否包含指定的字段或方法。
    * **Go 代码示例:** (与 `DotField` 和 `XDotField` 结合)
        ```go
        package main

        type Point struct {
            X int
            Y int
        }

        func (p Point) Add(other Point) Point {
            return Point{p.X + other.X, p.Y + other.Y}
        }

        func main() {
            p := Point{1, 2}
            _ = p.X       // tcDot 会检查 Point 类型是否有字段 X
            _ = p.Add     // tcDot 会检查 Point 类型是否有方法 Add
        }
        ```
        **假设输入:** 一个表示字段选择的 `ir.SelectorExpr` 节点。
        **输出:** 类型检查后的 `ir.Node`。

* **`tcDotType(n *ir.TypeAssertExpr) ir.Node`:**
    * **功能:** 类型检查类型断言表达式 (例如 `i.(int)`)。
    * **推理:**  检查接口类型是否确实实现了断言的类型。
    * **Go 代码示例:**
        ```go
        package main

        import "fmt"

        func main() {
            var i interface{} = 10
            if val, ok := i.(int); ok { // tcDotType 会检查 i 的动态类型是否是 int
                fmt.Println(val)
            }
            // _, ok := i.(string) // tcDotType 会检查 i 的动态类型是否是 string
        }
        ```
        **假设输入:** 一个表示类型断言的 `ir.TypeAssertExpr` 节点。
        **输出:** 类型检查后的 `ir.Node`。

* **`tcITab(n *ir.UnaryExpr) ir.Node`:**
    * **功能:** 类型检查 `itab` 操作，`itab` 是接口类型内部用于存储类型信息和方法表的结构。这个操作在源代码中不直接可见，通常是编译器内部使用。
    * **推理:**  确保操作对象是接口类型。

* **`tcIndex(n *ir.IndexExpr) ir.Node`:**
    * **功能:** 类型检查索引表达式 (例如 `array[i]`, `slice[j]`, `map[key]`, `string[k]`)。
    * **推理:**  检查索引类型是否为整数 (对于数组、切片、字符串) 或与 map 的键类型兼容。
    * **Go 代码示例:**
        ```go
        package main

        func main() {
            arr := [3]int{1, 2, 3}
            _ = arr[0] // tcIndex 会检查索引 0 是否是整数

            slice := []int{1, 2, 3}
            _ = slice[1] // tcIndex 会检查索引 1 是否是整数

            m := map[string]int{"a": 1}
            _ = m["a"] // tcIndex 会检查索引 "a" 是否是 string

            str := "hello"
            _ = str[0] // tcIndex 会检查索引 0 是否是整数
            // _ = arr["a"] // 编译错误，tcIndex 会检测到字符串不能作为数组的索引
        }
        ```
        **假设输入:** 一个表示索引操作的 `ir.IndexExpr` 节点。
        **输出:** 类型检查后的 `ir.Node`。

* **`tcLenCap(n *ir.UnaryExpr) ir.Node`:**
    * **功能:** 类型检查 `len()` 和 `cap()` 函数调用。
    * **推理:**  检查 `len()` 和 `cap()` 的参数类型是否是支持这些操作的类型 (例如数组、切片、map、字符串、channel)。
    * **Go 代码示例:**
        ```go
        package main

        func main() {
            arr := [3]int{1, 2, 3}
            _ = len(arr) // tcLenCap 会检查 len 的参数类型是否有效

            slice := []int{1, 2, 3}
            _ = cap(slice) // tcLenCap 会检查 cap 的参数类型是否有效
            // _ = len(10) // 编译错误，tcLenCap 会检测到整数不支持 len 操作
        }
        ```
        **假设输入:** 一个表示 `len` 或 `cap` 调用的 `ir.UnaryExpr` 节点。
        **输出:** 类型检查后的 `ir.Node`。

* **`tcUnsafeData(n *ir.UnaryExpr) ir.Node`:**
    * **功能:** 类型检查 `unsafe.SliceData()` 和 `unsafe.StringData()` 函数调用。
    * **推理:** 检查参数类型是否分别是切片或字符串。

* **`tcRecv(n *ir.UnaryExpr) ir.Node`:**
    * **功能:** 类型检查 channel 接收操作 (例如 `<-ch`)。
    * **推理:** 检查操作数是否是 channel 类型，并且是可接收的 channel。
    * **Go 代码示例:**
        ```go
        package main

        func main() {
            ch := make(chan int)
            _ = <-ch // tcRecv 会检查 ch 是否是可接收的 channel

            sendOnlyCh := make(chan<- int)
            // _ = <-sendOnlyCh // 编译错误，tcRecv 会检测到 send-only channel 不可接收
        }
        ```
        **假设输入:** 一个表示 channel 接收操作的 `ir.UnaryExpr` 节点。
        **输出:** 类型检查后的 `ir.Node`。

* **`tcSPtr(n *ir.UnaryExpr) ir.Node`:**
    * **功能:**  类型检查获取切片或字符串底层指针的操作 (在编译器内部使用，对应 `&s[0]` 或 `unsafe.SliceData(s)` 等)。
    * **推理:**  确保操作对象是切片或字符串。

* **`tcSlice(n *ir.SliceExpr) ir.Node`:**
    * **功能:** 类型检查切片表达式 (例如 `array[low:high]`, `slice[low:high:max]`)。
    * **推理:** 检查切片的索引是否是整数类型，并且符合切片的边界规则。
    * **Go 代码示例:**
        ```go
        package main

        func main() {
            arr := [5]int{1, 2, 3, 4, 5}
            _ = arr[1:3] // tcSlice 会检查索引 1 和 3 是否是整数

            slice := []int{1, 2, 3, 4, 5}
            _ = slice[1:3:4] // tcSlice 会检查索引 1, 3, 4 是否是整数
            // _ = arr["a":3] // 编译错误，tcSlice 会检测到字符串不能作为切片索引
        }
        ```
        **假设输入:** 一个表示切片操作的 `ir.SliceExpr` 节点。
        **输出:** 类型检查后的 `ir.Node`。

* **`tcSliceHeader(n *ir.SliceHeaderExpr) ir.Node`:**
    * **功能:** 类型检查 `reflect.SliceHeader` 相关的操作 (通常是编译器内部使用)。
    * **推理:** 检查 `Len` 和 `Cap` 字段是否为整数类型且非负。

* **`tcStringHeader(n *ir.StringHeaderExpr) ir.Node`:**
    * **功能:** 类型检查 `reflect.StringHeader` 相关的操作 (通常是编译器内部使用)。
    * **推理:** 检查 `Len` 字段是否为整数类型且非负。

* **`tcStar(n *ir.StarExpr, top int) ir.Node`:**
    * **功能:** 类型检查指针解引用操作 (例如 `*ptr`)。
    * **推理:** 检查操作数是否是指针类型。
    * **Go 代码示例:**
        ```go
        package main

        func main() {
            var i int = 10
            var ptr *int = &i
            _ = *ptr // tcStar 会检查 ptr 是否是指针类型
            // _ = *i   // 编译错误，tcStar 会检测到整数不是指针类型
        }
        ```
        **假设输入:** 一个表示指针解引用的 `ir.StarExpr` 节点。
        **输出:** 类型检查后的 `ir.Node`。

* **`tcUnaryArith(n *ir.UnaryExpr) ir.Node`:**
    * **功能:** 类型检查一元算术运算符 (例如 `+x`, `-y`, `^z`)。
    * **推理:** 检查操作数是否是数值类型。
    * **Go 代码示例:**
        ```go
        package main

        func main() {
            var i int = 10
            _ = -i // tcUnaryArith 会检查 i 是否是数值类型

            var b bool = true
            // _ = -b // 编译错误，tcUnaryArith 会检测到布尔类型不支持一元负号
        }
        ```
        **假设输入:** 一个表示一元算术运算的 `ir.UnaryExpr` 节点。
        **输出:** 类型检查后的 `ir.Node`。

**涉及的代码推理，带上假设的输入与输出:**

上面的每个函数的功能描述中都包含了假设的输入和输出示例。这些示例展示了类型检查器在处理不同表达式时可能接收到的内部表示 (`ir.Node`)，以及经过类型检查后返回的结果。

**涉及的命令行参数的具体处理:**

这段代码片段本身主要关注类型检查的逻辑，并没有直接处理命令行参数。Go 编译器的命令行参数处理通常在 `cmd/compile/internal/gc` 包中进行。然而，一些类型检查行为可能会受到编译选项的影响，例如是否启用某些优化或语言特性。这些选项通常会在编译器的初始化阶段被解析，并在类型检查过程中被访问。

**使用者易犯错的点:**

虽然这个代码是编译器内部的实现，但使用者 (Go 语言开发者) 容易犯的与这些类型检查相关的错误包括：

* **类型不匹配的运算:** 例如，尝试将字符串和数字相加，或对不兼容的类型进行比较。`tcArith` 会捕获这类错误。
* **在复合字面量中使用错误的类型:** 例如，在 `[]int` 中放入字符串，或在结构体字面量中使用不存在的字段名。`tcCompLit` 和 `tcStructLitKey` 会处理这些情况。
* **不合法的类型转换:** 尝试将无法转换的类型进行转换，例如将字符串直接转换为整数。`tcConv` 会进行检查。
* **对非指针类型进行解引用:** `tcStar` 会检测这类错误。
* **对不支持 `len` 或 `cap` 的类型使用这些函数:** `tcLenCap` 会进行检查。
* **对 channel 进行不合法的接收或发送操作:** `tcRecv` (对于接收) 和其他相关函数 (对于发送) 会进行类型检查。
* **切片操作中使用非整数索引或超出边界的索引:** `tcSlice` 和 `tcIndex` 会检查索引的有效性。

总而言之，这段 `expr.go` 代码是 Go 语言编译器类型检查的核心部分，它负责对各种 Go 语言表达式进行静态分析，确保程序的类型安全性。理解这部分代码有助于深入了解 Go 语言的类型系统以及编译器的工作原理。

### 提示词
```
这是路径为go/src/cmd/compile/internal/typecheck/expr.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"fmt"
	"go/constant"
	"go/token"
	"internal/types/errors"
	"strings"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/types"
	"cmd/internal/src"
)

func tcShift(n, l, r ir.Node) (ir.Node, ir.Node, *types.Type) {
	if l.Type() == nil || r.Type() == nil {
		return l, r, nil
	}

	r = DefaultLit(r, types.Types[types.TUINT])
	t := r.Type()
	if !t.IsInteger() {
		base.Errorf("invalid operation: %v (shift count type %v, must be integer)", n, r.Type())
		return l, r, nil
	}
	t = l.Type()
	if t != nil && t.Kind() != types.TIDEAL && !t.IsInteger() {
		base.Errorf("invalid operation: %v (shift of type %v)", n, t)
		return l, r, nil
	}

	// no DefaultLit for left
	// the outer context gives the type
	t = l.Type()
	if (l.Type() == types.UntypedFloat || l.Type() == types.UntypedComplex) && r.Op() == ir.OLITERAL {
		t = types.UntypedInt
	}
	return l, r, t
}

// tcArith typechecks operands of a binary arithmetic expression.
// The result of tcArith MUST be assigned back to original operands,
// t is the type of the expression, and should be set by the caller. e.g:
//
//	n.X, n.Y, t = tcArith(n, op, n.X, n.Y)
//	n.SetType(t)
func tcArith(n ir.Node, op ir.Op, l, r ir.Node) (ir.Node, ir.Node, *types.Type) {
	l, r = defaultlit2(l, r, false)
	if l.Type() == nil || r.Type() == nil {
		return l, r, nil
	}
	t := l.Type()
	if t.Kind() == types.TIDEAL {
		t = r.Type()
	}
	aop := ir.OXXX
	if n.Op().IsCmp() && t.Kind() != types.TIDEAL && !types.Identical(l.Type(), r.Type()) {
		// comparison is okay as long as one side is
		// assignable to the other.  convert so they have
		// the same type.
		//
		// the only conversion that isn't a no-op is concrete == interface.
		// in that case, check comparability of the concrete type.
		// The conversion allocates, so only do it if the concrete type is huge.
		converted := false
		if r.Type().Kind() != types.TBLANK {
			aop, _ = assignOp(l.Type(), r.Type())
			if aop != ir.OXXX {
				if r.Type().IsInterface() && !l.Type().IsInterface() && !types.IsComparable(l.Type()) {
					base.Errorf("invalid operation: %v (operator %v not defined on %s)", n, op, typekind(l.Type()))
					return l, r, nil
				}

				types.CalcSize(l.Type())
				if r.Type().IsInterface() == l.Type().IsInterface() || l.Type().Size() >= 1<<16 {
					l = ir.NewConvExpr(base.Pos, aop, r.Type(), l)
					l.SetTypecheck(1)
				}

				t = r.Type()
				converted = true
			}
		}

		if !converted && l.Type().Kind() != types.TBLANK {
			aop, _ = assignOp(r.Type(), l.Type())
			if aop != ir.OXXX {
				if l.Type().IsInterface() && !r.Type().IsInterface() && !types.IsComparable(r.Type()) {
					base.Errorf("invalid operation: %v (operator %v not defined on %s)", n, op, typekind(r.Type()))
					return l, r, nil
				}

				types.CalcSize(r.Type())
				if r.Type().IsInterface() == l.Type().IsInterface() || r.Type().Size() >= 1<<16 {
					r = ir.NewConvExpr(base.Pos, aop, l.Type(), r)
					r.SetTypecheck(1)
				}

				t = l.Type()
			}
		}
	}

	if t.Kind() != types.TIDEAL && !types.Identical(l.Type(), r.Type()) {
		l, r = defaultlit2(l, r, true)
		if l.Type() == nil || r.Type() == nil {
			return l, r, nil
		}
		if l.Type().IsInterface() == r.Type().IsInterface() || aop == 0 {
			base.Errorf("invalid operation: %v (mismatched types %v and %v)", n, l.Type(), r.Type())
			return l, r, nil
		}
	}

	if t.Kind() == types.TIDEAL {
		t = mixUntyped(l.Type(), r.Type())
	}
	if dt := defaultType(t); !okfor[op][dt.Kind()] {
		base.Errorf("invalid operation: %v (operator %v not defined on %s)", n, op, typekind(t))
		return l, r, nil
	}

	// okfor allows any array == array, map == map, func == func.
	// restrict to slice/map/func == nil and nil == slice/map/func.
	if l.Type().IsArray() && !types.IsComparable(l.Type()) {
		base.Errorf("invalid operation: %v (%v cannot be compared)", n, l.Type())
		return l, r, nil
	}

	if l.Type().IsSlice() && !ir.IsNil(l) && !ir.IsNil(r) {
		base.Errorf("invalid operation: %v (slice can only be compared to nil)", n)
		return l, r, nil
	}

	if l.Type().IsMap() && !ir.IsNil(l) && !ir.IsNil(r) {
		base.Errorf("invalid operation: %v (map can only be compared to nil)", n)
		return l, r, nil
	}

	if l.Type().Kind() == types.TFUNC && !ir.IsNil(l) && !ir.IsNil(r) {
		base.Errorf("invalid operation: %v (func can only be compared to nil)", n)
		return l, r, nil
	}

	if l.Type().IsStruct() {
		if f := types.IncomparableField(l.Type()); f != nil {
			base.Errorf("invalid operation: %v (struct containing %v cannot be compared)", n, f.Type)
			return l, r, nil
		}
	}

	return l, r, t
}

// The result of tcCompLit MUST be assigned back to n, e.g.
//
//	n.Left = tcCompLit(n.Left)
func tcCompLit(n *ir.CompLitExpr) (res ir.Node) {
	if base.EnableTrace && base.Flag.LowerT {
		defer tracePrint("tcCompLit", n)(&res)
	}

	lno := base.Pos
	defer func() {
		base.Pos = lno
	}()

	ir.SetPos(n)

	t := n.Type()
	base.AssertfAt(t != nil, n.Pos(), "missing type in composite literal")

	switch t.Kind() {
	default:
		base.Errorf("invalid composite literal type %v", t)
		n.SetType(nil)

	case types.TARRAY:
		typecheckarraylit(t.Elem(), t.NumElem(), n.List, "array literal")
		n.SetOp(ir.OARRAYLIT)

	case types.TSLICE:
		length := typecheckarraylit(t.Elem(), -1, n.List, "slice literal")
		n.SetOp(ir.OSLICELIT)
		n.Len = length

	case types.TMAP:
		for i3, l := range n.List {
			ir.SetPos(l)
			if l.Op() != ir.OKEY {
				n.List[i3] = Expr(l)
				base.Errorf("missing key in map literal")
				continue
			}
			l := l.(*ir.KeyExpr)

			r := l.Key
			r = Expr(r)
			l.Key = AssignConv(r, t.Key(), "map key")

			r = l.Value
			r = Expr(r)
			l.Value = AssignConv(r, t.Elem(), "map value")
		}

		n.SetOp(ir.OMAPLIT)

	case types.TSTRUCT:
		// Need valid field offsets for Xoffset below.
		types.CalcSize(t)

		errored := false
		if len(n.List) != 0 && nokeys(n.List) {
			// simple list of variables
			ls := n.List
			for i, n1 := range ls {
				ir.SetPos(n1)
				n1 = Expr(n1)
				ls[i] = n1
				if i >= t.NumFields() {
					if !errored {
						base.Errorf("too many values in %v", n)
						errored = true
					}
					continue
				}

				f := t.Field(i)
				s := f.Sym

				// Do the test for assigning to unexported fields.
				// But if this is an instantiated function, then
				// the function has already been typechecked. In
				// that case, don't do the test, since it can fail
				// for the closure structs created in
				// walkClosure(), because the instantiated
				// function is compiled as if in the source
				// package of the generic function.
				if !(ir.CurFunc != nil && strings.Contains(ir.CurFunc.Nname.Sym().Name, "[")) {
					if s != nil && !types.IsExported(s.Name) && s.Pkg != types.LocalPkg {
						base.Errorf("implicit assignment of unexported field '%s' in %v literal", s.Name, t)
					}
				}
				// No pushtype allowed here. Must name fields for that.
				n1 = AssignConv(n1, f.Type, "field value")
				ls[i] = ir.NewStructKeyExpr(base.Pos, f, n1)
			}
			if len(ls) < t.NumFields() {
				base.Errorf("too few values in %v", n)
			}
		} else {
			hash := make(map[string]bool)

			// keyed list
			ls := n.List
			for i, n := range ls {
				ir.SetPos(n)

				sk, ok := n.(*ir.StructKeyExpr)
				if !ok {
					kv, ok := n.(*ir.KeyExpr)
					if !ok {
						if !errored {
							base.Errorf("mixture of field:value and value initializers")
							errored = true
						}
						ls[i] = Expr(n)
						continue
					}

					sk = tcStructLitKey(t, kv)
					if sk == nil {
						continue
					}

					fielddup(sk.Sym().Name, hash)
				}

				// No pushtype allowed here. Tried and rejected.
				sk.Value = Expr(sk.Value)
				sk.Value = AssignConv(sk.Value, sk.Field.Type, "field value")
				ls[i] = sk
			}
		}

		n.SetOp(ir.OSTRUCTLIT)
	}

	return n
}

// tcStructLitKey typechecks an OKEY node that appeared within a
// struct literal.
func tcStructLitKey(typ *types.Type, kv *ir.KeyExpr) *ir.StructKeyExpr {
	key := kv.Key

	sym := key.Sym()

	// An OXDOT uses the Sym field to hold
	// the field to the right of the dot,
	// so s will be non-nil, but an OXDOT
	// is never a valid struct literal key.
	if sym == nil || sym.Pkg != types.LocalPkg || key.Op() == ir.OXDOT || sym.IsBlank() {
		base.Errorf("invalid field name %v in struct initializer", key)
		return nil
	}

	if f := Lookdot1(nil, sym, typ, typ.Fields(), 0); f != nil {
		return ir.NewStructKeyExpr(kv.Pos(), f, kv.Value)
	}

	if ci := Lookdot1(nil, sym, typ, typ.Fields(), 2); ci != nil { // Case-insensitive lookup.
		if visible(ci.Sym) {
			base.Errorf("unknown field '%v' in struct literal of type %v (but does have %v)", sym, typ, ci.Sym)
		} else if nonexported(sym) && sym.Name == ci.Sym.Name { // Ensure exactness before the suggestion.
			base.Errorf("cannot refer to unexported field '%v' in struct literal of type %v", sym, typ)
		} else {
			base.Errorf("unknown field '%v' in struct literal of type %v", sym, typ)
		}
		return nil
	}

	var f *types.Field
	p, _ := dotpath(sym, typ, &f, true)
	if p == nil || f.IsMethod() {
		base.Errorf("unknown field '%v' in struct literal of type %v", sym, typ)
		return nil
	}

	// dotpath returns the parent embedded types in reverse order.
	var ep []string
	for ei := len(p) - 1; ei >= 0; ei-- {
		ep = append(ep, p[ei].field.Sym.Name)
	}
	ep = append(ep, sym.Name)
	base.Errorf("cannot use promoted field %v in struct literal of type %v", strings.Join(ep, "."), typ)
	return nil
}

// tcConv typechecks an OCONV node.
func tcConv(n *ir.ConvExpr) ir.Node {
	types.CheckSize(n.Type()) // ensure width is calculated for backend
	n.X = Expr(n.X)
	n.X = convlit1(n.X, n.Type(), true, nil)
	t := n.X.Type()
	if t == nil || n.Type() == nil {
		n.SetType(nil)
		return n
	}
	op, why := convertOp(n.X.Op() == ir.OLITERAL, t, n.Type())
	if op == ir.OXXX {
		// Due to //go:nointerface, we may be stricter than types2 here (#63333).
		base.ErrorfAt(n.Pos(), errors.InvalidConversion, "cannot convert %L to type %v%s", n.X, n.Type(), why)
		n.SetType(nil)
		return n
	}

	n.SetOp(op)
	switch n.Op() {
	case ir.OCONVNOP:
		if t.Kind() == n.Type().Kind() {
			switch t.Kind() {
			case types.TFLOAT32, types.TFLOAT64, types.TCOMPLEX64, types.TCOMPLEX128:
				// Floating point casts imply rounding and
				// so the conversion must be kept.
				n.SetOp(ir.OCONV)
			}
		}

	// do not convert to []byte literal. See CL 125796.
	// generated code and compiler memory footprint is better without it.
	case ir.OSTR2BYTES:
		// ok

	case ir.OSTR2RUNES:
		if n.X.Op() == ir.OLITERAL {
			return stringtoruneslit(n)
		}

	case ir.OBYTES2STR:
		if t.Elem() != types.ByteType && t.Elem() != types.Types[types.TUINT8] {
			// If t is a slice of a user-defined byte type B (not uint8
			// or byte), then add an extra CONVNOP from []B to []byte, so
			// that the call to slicebytetostring() added in walk will
			// typecheck correctly.
			n.X = ir.NewConvExpr(n.X.Pos(), ir.OCONVNOP, types.NewSlice(types.ByteType), n.X)
			n.X.SetTypecheck(1)
		}

	case ir.ORUNES2STR:
		if t.Elem() != types.RuneType && t.Elem() != types.Types[types.TINT32] {
			// If t is a slice of a user-defined rune type B (not uint32
			// or rune), then add an extra CONVNOP from []B to []rune, so
			// that the call to slicerunetostring() added in walk will
			// typecheck correctly.
			n.X = ir.NewConvExpr(n.X.Pos(), ir.OCONVNOP, types.NewSlice(types.RuneType), n.X)
			n.X.SetTypecheck(1)
		}

	}
	return n
}

// DotField returns a field selector expression that selects the
// index'th field of the given expression, which must be of struct or
// pointer-to-struct type.
func DotField(pos src.XPos, x ir.Node, index int) *ir.SelectorExpr {
	op, typ := ir.ODOT, x.Type()
	if typ.IsPtr() {
		op, typ = ir.ODOTPTR, typ.Elem()
	}
	if !typ.IsStruct() {
		base.FatalfAt(pos, "DotField of non-struct: %L", x)
	}

	// TODO(mdempsky): This is the backend's responsibility.
	types.CalcSize(typ)

	field := typ.Field(index)
	return dot(pos, field.Type, op, x, field)
}

func dot(pos src.XPos, typ *types.Type, op ir.Op, x ir.Node, selection *types.Field) *ir.SelectorExpr {
	n := ir.NewSelectorExpr(pos, op, x, selection.Sym)
	n.Selection = selection
	n.SetType(typ)
	n.SetTypecheck(1)
	return n
}

// XDotField returns an expression representing the field selection
// x.sym. If any implicit field selection are necessary, those are
// inserted too.
func XDotField(pos src.XPos, x ir.Node, sym *types.Sym) *ir.SelectorExpr {
	n := Expr(ir.NewSelectorExpr(pos, ir.OXDOT, x, sym)).(*ir.SelectorExpr)
	if n.Op() != ir.ODOT && n.Op() != ir.ODOTPTR {
		base.FatalfAt(pos, "unexpected result op: %v (%v)", n.Op(), n)
	}
	return n
}

// XDotMethod returns an expression representing the method value
// x.sym (i.e., x is a value, not a type). If any implicit field
// selection are necessary, those are inserted too.
//
// If callee is true, the result is an ODOTMETH/ODOTINTER, otherwise
// an OMETHVALUE.
func XDotMethod(pos src.XPos, x ir.Node, sym *types.Sym, callee bool) *ir.SelectorExpr {
	n := ir.NewSelectorExpr(pos, ir.OXDOT, x, sym)
	if callee {
		n = Callee(n).(*ir.SelectorExpr)
		if n.Op() != ir.ODOTMETH && n.Op() != ir.ODOTINTER {
			base.FatalfAt(pos, "unexpected result op: %v (%v)", n.Op(), n)
		}
	} else {
		n = Expr(n).(*ir.SelectorExpr)
		if n.Op() != ir.OMETHVALUE {
			base.FatalfAt(pos, "unexpected result op: %v (%v)", n.Op(), n)
		}
	}
	return n
}

// tcDot typechecks an OXDOT or ODOT node.
func tcDot(n *ir.SelectorExpr, top int) ir.Node {
	if n.Op() == ir.OXDOT {
		n = AddImplicitDots(n)
		n.SetOp(ir.ODOT)
		if n.X == nil {
			n.SetType(nil)
			return n
		}
	}

	n.X = Expr(n.X)
	n.X = DefaultLit(n.X, nil)

	t := n.X.Type()
	if t == nil {
		base.UpdateErrorDot(ir.Line(n), fmt.Sprint(n.X), fmt.Sprint(n))
		n.SetType(nil)
		return n
	}

	if n.X.Op() == ir.OTYPE {
		base.FatalfAt(n.Pos(), "use NewMethodExpr to construct OMETHEXPR")
	}

	if t.IsPtr() && !t.Elem().IsInterface() {
		t = t.Elem()
		if t == nil {
			n.SetType(nil)
			return n
		}
		n.SetOp(ir.ODOTPTR)
		types.CheckSize(t)
	}

	if n.Sel.IsBlank() {
		base.Errorf("cannot refer to blank field or method")
		n.SetType(nil)
		return n
	}

	if Lookdot(n, t, 0) == nil {
		// Legitimate field or method lookup failed, try to explain the error
		switch {
		case t.IsEmptyInterface():
			base.Errorf("%v undefined (type %v is interface with no methods)", n, n.X.Type())

		case t.IsPtr() && t.Elem().IsInterface():
			// Pointer to interface is almost always a mistake.
			base.Errorf("%v undefined (type %v is pointer to interface, not interface)", n, n.X.Type())

		case Lookdot(n, t, 1) != nil:
			// Field or method matches by name, but it is not exported.
			base.Errorf("%v undefined (cannot refer to unexported field or method %v)", n, n.Sel)

		default:
			if mt := Lookdot(n, t, 2); mt != nil && visible(mt.Sym) { // Case-insensitive lookup.
				base.Errorf("%v undefined (type %v has no field or method %v, but does have %v)", n, n.X.Type(), n.Sel, mt.Sym)
			} else {
				base.Errorf("%v undefined (type %v has no field or method %v)", n, n.X.Type(), n.Sel)
			}
		}
		n.SetType(nil)
		return n
	}

	if (n.Op() == ir.ODOTINTER || n.Op() == ir.ODOTMETH) && top&ctxCallee == 0 {
		n.SetOp(ir.OMETHVALUE)
		n.SetType(NewMethodType(n.Type(), nil))
	}
	return n
}

// tcDotType typechecks an ODOTTYPE node.
func tcDotType(n *ir.TypeAssertExpr) ir.Node {
	n.X = Expr(n.X)
	n.X = DefaultLit(n.X, nil)
	l := n.X
	t := l.Type()
	if t == nil {
		n.SetType(nil)
		return n
	}
	if !t.IsInterface() {
		base.Errorf("invalid type assertion: %v (non-interface type %v on left)", n, t)
		n.SetType(nil)
		return n
	}

	base.AssertfAt(n.Type() != nil, n.Pos(), "missing type: %v", n)

	if n.Type() != nil && !n.Type().IsInterface() {
		why := ImplementsExplain(n.Type(), t)
		if why != "" {
			base.Fatalf("impossible type assertion:\n\t%s", why)
			n.SetType(nil)
			return n
		}
	}
	return n
}

// tcITab typechecks an OITAB node.
func tcITab(n *ir.UnaryExpr) ir.Node {
	n.X = Expr(n.X)
	t := n.X.Type()
	if t == nil {
		n.SetType(nil)
		return n
	}
	if !t.IsInterface() {
		base.Fatalf("OITAB of %v", t)
	}
	n.SetType(types.NewPtr(types.Types[types.TUINTPTR]))
	return n
}

// tcIndex typechecks an OINDEX node.
func tcIndex(n *ir.IndexExpr) ir.Node {
	n.X = Expr(n.X)
	n.X = DefaultLit(n.X, nil)
	n.X = implicitstar(n.X)
	l := n.X
	n.Index = Expr(n.Index)
	r := n.Index
	t := l.Type()
	if t == nil || r.Type() == nil {
		n.SetType(nil)
		return n
	}
	switch t.Kind() {
	default:
		base.Errorf("invalid operation: %v (type %v does not support indexing)", n, t)
		n.SetType(nil)
		return n

	case types.TSTRING, types.TARRAY, types.TSLICE:
		n.Index = indexlit(n.Index)
		if t.IsString() {
			n.SetType(types.ByteType)
		} else {
			n.SetType(t.Elem())
		}
		why := "string"
		if t.IsArray() {
			why = "array"
		} else if t.IsSlice() {
			why = "slice"
		}

		if n.Index.Type() != nil && !n.Index.Type().IsInteger() {
			base.Errorf("non-integer %s index %v", why, n.Index)
			return n
		}

	case types.TMAP:
		n.Index = AssignConv(n.Index, t.Key(), "map index")
		n.SetType(t.Elem())
		n.SetOp(ir.OINDEXMAP)
		n.Assigned = false
	}
	return n
}

// tcLenCap typechecks an OLEN or OCAP node.
func tcLenCap(n *ir.UnaryExpr) ir.Node {
	n.X = Expr(n.X)
	n.X = DefaultLit(n.X, nil)
	n.X = implicitstar(n.X)
	l := n.X
	t := l.Type()
	if t == nil {
		n.SetType(nil)
		return n
	}

	var ok bool
	if n.Op() == ir.OLEN {
		ok = okforlen[t.Kind()]
	} else {
		ok = okforcap[t.Kind()]
	}
	if !ok {
		base.Errorf("invalid argument %L for %v", l, n.Op())
		n.SetType(nil)
		return n
	}

	n.SetType(types.Types[types.TINT])
	return n
}

// tcUnsafeData typechecks an OUNSAFESLICEDATA or OUNSAFESTRINGDATA node.
func tcUnsafeData(n *ir.UnaryExpr) ir.Node {
	n.X = Expr(n.X)
	n.X = DefaultLit(n.X, nil)
	l := n.X
	t := l.Type()
	if t == nil {
		n.SetType(nil)
		return n
	}

	var kind types.Kind
	if n.Op() == ir.OUNSAFESLICEDATA {
		kind = types.TSLICE
	} else {
		/* kind is string */
		kind = types.TSTRING
	}

	if t.Kind() != kind {
		base.Errorf("invalid argument %L for %v", l, n.Op())
		n.SetType(nil)
		return n
	}

	if kind == types.TSTRING {
		t = types.ByteType
	} else {
		t = t.Elem()
	}
	n.SetType(types.NewPtr(t))
	return n
}

// tcRecv typechecks an ORECV node.
func tcRecv(n *ir.UnaryExpr) ir.Node {
	n.X = Expr(n.X)
	n.X = DefaultLit(n.X, nil)
	l := n.X
	t := l.Type()
	if t == nil {
		n.SetType(nil)
		return n
	}
	if !t.IsChan() {
		base.Errorf("invalid operation: %v (receive from non-chan type %v)", n, t)
		n.SetType(nil)
		return n
	}

	if !t.ChanDir().CanRecv() {
		base.Errorf("invalid operation: %v (receive from send-only type %v)", n, t)
		n.SetType(nil)
		return n
	}

	n.SetType(t.Elem())
	return n
}

// tcSPtr typechecks an OSPTR node.
func tcSPtr(n *ir.UnaryExpr) ir.Node {
	n.X = Expr(n.X)
	t := n.X.Type()
	if t == nil {
		n.SetType(nil)
		return n
	}
	if !t.IsSlice() && !t.IsString() {
		base.Fatalf("OSPTR of %v", t)
	}
	if t.IsString() {
		n.SetType(types.NewPtr(types.Types[types.TUINT8]))
	} else {
		n.SetType(types.NewPtr(t.Elem()))
	}
	return n
}

// tcSlice typechecks an OSLICE or OSLICE3 node.
func tcSlice(n *ir.SliceExpr) ir.Node {
	n.X = DefaultLit(Expr(n.X), nil)
	n.Low = indexlit(Expr(n.Low))
	n.High = indexlit(Expr(n.High))
	n.Max = indexlit(Expr(n.Max))
	hasmax := n.Op().IsSlice3()
	l := n.X
	if l.Type() == nil {
		n.SetType(nil)
		return n
	}
	if l.Type().IsArray() {
		if !ir.IsAddressable(n.X) {
			base.Errorf("invalid operation %v (slice of unaddressable value)", n)
			n.SetType(nil)
			return n
		}

		addr := NodAddr(n.X)
		addr.SetImplicit(true)
		n.X = Expr(addr)
		l = n.X
	}
	t := l.Type()
	var tp *types.Type
	if t.IsString() {
		if hasmax {
			base.Errorf("invalid operation %v (3-index slice of string)", n)
			n.SetType(nil)
			return n
		}
		n.SetType(t)
		n.SetOp(ir.OSLICESTR)
	} else if t.IsPtr() && t.Elem().IsArray() {
		tp = t.Elem()
		n.SetType(types.NewSlice(tp.Elem()))
		types.CalcSize(n.Type())
		if hasmax {
			n.SetOp(ir.OSLICE3ARR)
		} else {
			n.SetOp(ir.OSLICEARR)
		}
	} else if t.IsSlice() {
		n.SetType(t)
	} else {
		base.Errorf("cannot slice %v (type %v)", l, t)
		n.SetType(nil)
		return n
	}

	if n.Low != nil && !checksliceindex(n.Low) {
		n.SetType(nil)
		return n
	}
	if n.High != nil && !checksliceindex(n.High) {
		n.SetType(nil)
		return n
	}
	if n.Max != nil && !checksliceindex(n.Max) {
		n.SetType(nil)
		return n
	}
	return n
}

// tcSliceHeader typechecks an OSLICEHEADER node.
func tcSliceHeader(n *ir.SliceHeaderExpr) ir.Node {
	// Errors here are Fatalf instead of Errorf because only the compiler
	// can construct an OSLICEHEADER node.
	// Components used in OSLICEHEADER that are supplied by parsed source code
	// have already been typechecked in e.g. OMAKESLICE earlier.
	t := n.Type()
	if t == nil {
		base.Fatalf("no type specified for OSLICEHEADER")
	}

	if !t.IsSlice() {
		base.Fatalf("invalid type %v for OSLICEHEADER", n.Type())
	}

	if n.Ptr == nil || n.Ptr.Type() == nil || !n.Ptr.Type().IsUnsafePtr() {
		base.Fatalf("need unsafe.Pointer for OSLICEHEADER")
	}

	n.Ptr = Expr(n.Ptr)
	n.Len = DefaultLit(Expr(n.Len), types.Types[types.TINT])
	n.Cap = DefaultLit(Expr(n.Cap), types.Types[types.TINT])

	if ir.IsConst(n.Len, constant.Int) && ir.Int64Val(n.Len) < 0 {
		base.Fatalf("len for OSLICEHEADER must be non-negative")
	}

	if ir.IsConst(n.Cap, constant.Int) && ir.Int64Val(n.Cap) < 0 {
		base.Fatalf("cap for OSLICEHEADER must be non-negative")
	}

	if ir.IsConst(n.Len, constant.Int) && ir.IsConst(n.Cap, constant.Int) && constant.Compare(n.Len.Val(), token.GTR, n.Cap.Val()) {
		base.Fatalf("len larger than cap for OSLICEHEADER")
	}

	return n
}

// tcStringHeader typechecks an OSTRINGHEADER node.
func tcStringHeader(n *ir.StringHeaderExpr) ir.Node {
	t := n.Type()
	if t == nil {
		base.Fatalf("no type specified for OSTRINGHEADER")
	}

	if !t.IsString() {
		base.Fatalf("invalid type %v for OSTRINGHEADER", n.Type())
	}

	if n.Ptr == nil || n.Ptr.Type() == nil || !n.Ptr.Type().IsUnsafePtr() {
		base.Fatalf("need unsafe.Pointer for OSTRINGHEADER")
	}

	n.Ptr = Expr(n.Ptr)
	n.Len = DefaultLit(Expr(n.Len), types.Types[types.TINT])

	if ir.IsConst(n.Len, constant.Int) && ir.Int64Val(n.Len) < 0 {
		base.Fatalf("len for OSTRINGHEADER must be non-negative")
	}

	return n
}

// tcStar typechecks an ODEREF node, which may be an expression or a type.
func tcStar(n *ir.StarExpr, top int) ir.Node {
	n.X = typecheck(n.X, ctxExpr|ctxType)
	l := n.X
	t := l.Type()
	if t == nil {
		n.SetType(nil)
		return n
	}

	// TODO(mdempsky): Remove (along with ctxType above) once I'm
	// confident this code path isn't needed any more.
	if l.Op() == ir.OTYPE {
		base.Fatalf("unexpected type in deref expression: %v", l)
	}

	if !t.IsPtr() {
		if top&(ctxExpr|ctxStmt) != 0 {
			base.Errorf("invalid indirect of %L", n.X)
			n.SetType(nil)
			return n
		}
		base.Errorf("%v is not a type", l)
		return n
	}

	n.SetType(t.Elem())
	return n
}

// tcUnaryArith typechecks a unary arithmetic expression.
func tcUnaryArith(n *ir.UnaryExpr) ir.Node {
	n.X = Expr(n.X)
	l := n.X
	t := l.Type()
	if t == nil {
		n.SetType(nil)
		return n
	}
	if !okfor[n.Op()][defaultType(t).Kind()] {
		base.Errorf("invalid operation: %v (operator %v not defined on %s)", n, n.Op(), typekind(t))
		n.SetType(nil)
		return n
	}

	n.SetType(t)
	return n
}
```